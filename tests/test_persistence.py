import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from core import (
    AuditPersistenceError,
    CoreOrchestrator,
    Database,
    Persistence,
    RunContext,
    RunRepository,
    RunState,
)


def valid_scope() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "engagement_id": "engagement-persistence",
        "environment": "test",
        "mode": "test",
        "valid_from_utc": (now - timedelta(minutes=1)).isoformat(),
        "valid_until_utc": (now + timedelta(hours=1)).isoformat(),
        "allowed_targets": ["example.test"],
        "allowed_modules": ["health_check"],
        "limits": {
            "max_duration_seconds": 120,
            "max_rate_per_second": 5,
            "max_concurrency": 2,
            "max_volume_bytes": 100000,
            "measurement_window_seconds": 30,
        },
    }


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_path = Path(self.temp_dir.name) / "engine.sqlite3"

    def test_migrations_and_integrity_check_survive_restart(self) -> None:
        database = Database(self.database_path)
        with database.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, 1)
        self.assertEqual(database.integrity_check(), ("ok",))
        database.close()

        reopened = Database(self.database_path)
        self.assertEqual(reopened.integrity_check(), ("ok",))
        reopened.close()

    def test_nested_transactions_rollback_atomically(self) -> None:
        database = Database(self.database_path)
        runs = RunRepository(database)
        run_id = uuid4()
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            with database.transaction():
                runs.create(run_id, "test")
                raise RuntimeError("rollback")

        self.assertIsNone(runs.get(run_id))
        database.close()

    def test_foreign_keys_reject_orphaned_metrics(self) -> None:
        persistence = Persistence(
            self.database_path, Path(self.temp_dir.name) / "audit.jsonl"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            persistence.metrics.create(
                uuid4(), "latency", 10, unit="ms"
            )
        persistence.close()


class PersistenceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.database_path = self.root / "engine.sqlite3"
        self.audit_path = self.root / "audit" / "events.jsonl"
        self.scope_path = self.root / "scope.json"
        self.scope_path.write_text(json.dumps(valid_scope()), encoding="utf-8")

    def test_critical_events_are_persisted_exported_and_redacted(self) -> None:
        persistence = Persistence(self.database_path, self.audit_path)
        orchestrator = CoreOrchestrator(persistence=persistence)
        run = orchestrator.create_run("test")
        orchestrator.validate_scope(
            run.run_id,
            str(self.scope_path),
            engagement_id="engagement-persistence",
            environment="test",
            targets=["example.test"],
            modules=["health_check"],
        )
        orchestrator.transition(run.run_id, RunState.RUNNING)

        persistence.record_metric(
            run.run_id,
            "response_latency",
            125.5,
            unit="ms",
            dimensions={"api_key": "do-not-log-this"},
        )
        finding = persistence.create_finding(
            run.run_id,
            severity="medium",
            title="Credential check",
            description="token=do-not-log-this",
            details={
                "api_key": "do-not-log-this",
                "context": "Authorization: Bearer do-not-log-this",
            },
        )
        approval = persistence.create_approval(
            run.run_id,
            approver="operator",
            decision="approved",
            details={"password": "do-not-log-this"},
        )
        self.assertEqual(finding.details["api_key"], "[REDACTED]")
        self.assertEqual(approval.details["password"], "[REDACTED]")

        orchestrator.kill_switch.trigger(
            "password=do-not-log-this",
            reason_code="manual",
            run_id=run.run_id,
        )
        self.assertEqual(
            orchestrator.get_state(run.run_id), RunState.STOPPED
        )

        events = persistence.events.list_for_run(run.run_id)
        critical_names = {event.name for event in events}
        self.assertTrue(
            {
                "scope.validated",
                "run.started",
                "metric.sample",
                "safety.triggered",
                "run.stopped",
                "finding.created",
            }.issubset(critical_names)
        )
        run_record = persistence.runs.get(run.run_id)
        self.assertIsNotNone(run_record)
        self.assertEqual(run_record.state, "STOPPED")
        self.assertEqual(run_record.engagement_id, "engagement-persistence")
        self.assertEqual(len(persistence.events.list_critical()), 6)

        export_path = persistence.export_jsonl(self.root / "exports" / "audit.jsonl")
        lines = export_path.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        exported_names = {record["event_type"] for record in records}
        self.assertTrue(
            {
                "scope.validated",
                "run.started",
                "metric.sample",
                "safety.triggered",
                "run.stopped",
                "finding.created",
            }.issubset(exported_names)
        )
        exported_text = export_path.read_text(encoding="utf-8")
        self.assertNotIn("do-not-log-this", exported_text)
        persistence.close()

        reopened = Persistence(self.database_path, self.audit_path)
        self.assertEqual(reopened.runs.get(run.run_id).state, "STOPPED")
        self.assertEqual(
            len(reopened.events.list_for_run(run.run_id)),
            len(events),
        )
        self.assertEqual(len(reopened.metrics.list_for_run(run.run_id)), 1)
        persisted_findings = reopened.findings.list_for_run(run.run_id)
        self.assertEqual(len(persisted_findings), 1)
        self.assertEqual(persisted_findings[0].details["api_key"], "[REDACTED]")
        persisted_approvals = reopened.approvals.list_for_run(run.run_id)
        self.assertEqual(len(persisted_approvals), 1)
        self.assertEqual(persisted_approvals[0].details["password"], "[REDACTED]")
        reopened.close()

    def test_unknown_event_payload_is_omitted_from_audit_log(self) -> None:
        from core.events import Event, EventBus

        persistence = Persistence(self.database_path, self.audit_path)
        bus = EventBus()
        persistence.attach(bus)
        bus.publish(
            Event(
                run_id=None,
                name="custom-token=private",
                payload={"password": "never-write", "message": "secret=never-write"},
            )
        )
        log_text = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn("never-write", log_text)
        self.assertIn('"event_type":"event.other"', log_text)
        persistence.close()

    def test_audit_write_failure_rolls_back_and_blocks_execution(self) -> None:
        not_a_directory = self.root / "not-a-directory"
        not_a_directory.write_text("block log directory creation", encoding="utf-8")
        persistence = Persistence(
            self.database_path,
            not_a_directory / "audit.jsonl",
        )
        orchestrator = CoreOrchestrator(persistence=persistence)
        run = RunContext.create("test")

        with self.assertRaises(AuditPersistenceError):
            orchestrator.register_run(run)

        self.assertTrue(orchestrator.kill_switch.is_triggered)
        self.assertEqual(
            orchestrator.get_state(run.run_id), RunState.BLOCKED
        )
        self.assertIsNone(persistence.runs.get(run.run_id))
        persistence.close()


if __name__ == "__main__":
    unittest.main()
