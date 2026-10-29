import csv
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import (
    AuditReportService,
    CoreOrchestrator,
    Persistence,
    ReportGenerationError,
    RunState,
    ScopeValidator,
)


class AuditReportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.scope_path = self.root / "scope.json"
        now = datetime.now(timezone.utc)
        scope_document = {
            "engagement_id": "report-engagement",
            "environment": "test",
            "mode": "audit",
            "valid_from_utc": (now - timedelta(minutes=1)).isoformat(),
            "valid_until_utc": (now + timedelta(hours=1)).isoformat(),
            "allowed_targets": ["localhost"],
            "allowed_modules": ["telemetry_demo"],
            "limits": {
                "max_duration_seconds": 60,
                "max_rate_per_second": 10,
                "max_concurrency": 1,
                "max_volume_bytes": 100_000,
                "measurement_window_seconds": 30,
            },
        }
        self.scope_path.write_text(
            json.dumps(scope_document, sort_keys=True),
            encoding="utf-8",
        )
        self.persistence = Persistence(
            self.root / "engine.sqlite3",
            self.root / "audit.jsonl",
        )
        self.addCleanup(self.persistence.close)
        self.orchestrator = CoreOrchestrator(persistence=self.persistence)
        self.run = self.orchestrator.create_run("audit")
        self.orchestrator.validate_scope(
            self.run.run_id,
            str(self.scope_path),
            engagement_id="report-engagement",
            environment="test",
            targets=["localhost"],
            modules=["telemetry_demo"],
            validator=ScopeValidator(),
        )
        self.orchestrator.transition(self.run.run_id, RunState.RUNNING)

    def test_build_report_has_required_fields_and_real_scope_hash(self) -> None:
        self.orchestrator.record_module_execution(
            self.run.run_id,
            "telemetry_demo",
        )
        self.persistence.record_metric(
            self.run.run_id,
            "rtt_ms",
            20,
            unit="ms",
        )
        self.persistence.record_metric(
            self.run.run_id,
            "rtt_ms",
            40,
            unit="ms",
        )
        self.persistence.create_finding(
            self.run.run_id,
            severity="low",
            title="Observed condition",
            description="token=report-secret",
            details={
                "evidence": "Authorization: Bearer report-secret",
                "api_key": "report-secret",
            },
        )
        self.orchestrator.kill_switch.trigger(
            "Manual stop",
            reason_code="manual_interruption",
            run_id=self.run.run_id,
        )

        report = AuditReportService(self.orchestrator).build_report(
            self.run.run_id,
            operator="operator token=report-secret",
        )

        self.assertEqual(
            set(report),
            {
                "report_id",
                "system",
                "operator",
                "scope",
                "execution",
                "metrics",
                "findings",
                "kill_switch",
                "stop_reason",
                "limitations",
                "recommendations",
            },
        )
        self.assertEqual(
            report["scope"]["sha256"],
            hashlib.sha256(self.scope_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["execution"]["modules_executed"], ["telemetry_demo"])
        self.assertIsNotNone(report["execution"]["started_at_utc"])
        self.assertIsNotNone(report["execution"]["ended_at_utc"])
        self.assertEqual(report["metrics"]["rtt_ms"]["count"], 2)
        self.assertEqual(report["metrics"]["rtt_ms"]["mean"], 30)
        self.assertEqual(report["stop_reason"], "manual_interruption")
        self.assertTrue(report["kill_switch"]["triggered"])
        self.assertEqual(len(report["kill_switch"]["events"]), 1)

        rendered_report = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("report-secret", rendered_report)
        self.assertIn("[REDACTED]", rendered_report)

    def test_json_and_csv_exports_preserve_report_fields(self) -> None:
        self.orchestrator.kill_switch.trigger(
            "Manual stop",
            reason_code="manual_interruption",
            run_id=self.run.run_id,
        )
        report = AuditReportService(self.orchestrator).build_report(
            self.run.run_id,
            operator="auditor",
        )
        json_path = AuditReportService.export_json(
            report,
            self.root / "reports" / "audit.json",
        )
        csv_path = AuditReportService.export_csv(
            report,
            self.root / "reports" / "audit.csv",
        )

        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        with csv_path.open(encoding="utf-8", newline="") as source:
            csv_rows = list(csv.DictReader(source))
        csv_sections = {row["section"] for row in csv_rows}
        self.assertEqual(loaded, report)
        self.assertEqual(csv_sections, set(report))
        self.assertTrue(all(row["data_json"] for row in csv_rows))

    def test_report_requires_validated_scope_and_complete_fields(self) -> None:
        with self.assertRaises(ReportGenerationError):
            AuditReportService.validate_report({"report_id": "incomplete"})

        orchestrator = CoreOrchestrator()
        run = orchestrator.create_run("test")
        with self.assertRaises(ReportGenerationError):
            AuditReportService(orchestrator).build_report(
                run.run_id,
                operator="auditor",
            )

    def test_module_execution_must_be_authorized_and_running(self) -> None:
        with self.assertRaises(ValueError):
            self.orchestrator.record_module_execution(
                self.run.run_id,
                "unauthorized",
            )


if __name__ == "__main__":
    unittest.main()
