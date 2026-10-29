import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import (
    CoreOrchestrator,
    KillSwitch,
    KillSwitchTriggered,
    OperationalLimitEnforcer,
    OperationalLimitExceeded,
    RunContext,
    RunState,
    ScopeLimits,
    ScopeValidationError,
    ScopeValidator,
)


NOW = datetime(2026, 10, 29, 15, 0, tzinfo=timezone.utc)


def scope_document(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
        "engagement_id": "engagement-1",
        "environment": "staging",
        "mode": "test",
        "valid_from_utc": (NOW - timedelta(minutes=5)).isoformat(),
        "valid_until_utc": (NOW + timedelta(hours=1)).isoformat(),
        "allowed_targets": ["api.example.test", "192.0.2.10"],
        "allowed_modules": ["inventory", "health_check"],
        "limits": {
            "max_duration_seconds": 60,
            "max_rate_per_second": 10,
            "max_concurrency": 2,
            "max_volume_bytes": 1000,
            "measurement_window_seconds": 30,
        },
    }
    document.update(updates)
    return document


class ScopeValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.scope_path = Path(self.temp_dir.name) / "scope.json"
        self.validator = ScopeValidator(clock=lambda: NOW)

    def write_scope(self, document: dict[str, object]) -> None:
        self.scope_path.write_text(json.dumps(document), encoding="utf-8")

    def validate(self, **overrides: object):
        arguments: dict[str, object] = {
            "engagement_id": "engagement-1",
            "environment": "staging",
            "mode": "test",
            "targets": ["api.example.test"],
            "modules": ["inventory"],
        }
        arguments.update(overrides)
        return self.validator.validate(self.scope_path, **arguments)  # type: ignore[arg-type]

    def test_accepts_valid_scope_and_returns_required_limits(self) -> None:
        self.write_scope(scope_document())

        validated = self.validate()

        self.assertEqual(validated.engagement_id, "engagement-1")
        self.assertEqual(validated.allowed_targets, {"api.example.test", "192.0.2.10"})
        self.assertEqual(validated.limits.max_volume_bytes, 1000)

    def test_rejects_missing_or_malformed_scope_file(self) -> None:
        with self.assertRaises(ScopeValidationError):
            self.validate()

        self.scope_path.write_text("{", encoding="utf-8")
        with self.assertRaises(ScopeValidationError):
            self.validate()

    def test_rejects_expired_or_not_yet_valid_scope(self) -> None:
        expired = scope_document(
            valid_until_utc=(NOW - timedelta(seconds=1)).isoformat()
        )
        self.write_scope(expired)
        with self.assertRaises(ScopeValidationError):
            self.validate()

        future = scope_document(
            valid_from_utc=(NOW + timedelta(seconds=1)).isoformat()
        )
        self.write_scope(future)
        with self.assertRaises(ScopeValidationError):
            self.validate()

    def test_rejects_invalid_engagement_environment_mode_and_schema(self) -> None:
        self.write_scope(scope_document())
        for field, value in (
            ("engagement_id", "other"),
            ("environment", "production"),
            ("mode", "other"),
        ):
            arguments = {field: value}
            with self.subTest(field=field):
                with self.assertRaises(ScopeValidationError):
                    self.validate(**arguments)

        self.write_scope(scope_document(unexpected="value"))
        with self.assertRaises(ScopeValidationError):
            self.validate()

        invalid_limits = scope_document(
            limits={
                "max_duration_seconds": 60,
                "max_rate_per_second": float("inf"),
                "max_concurrency": 2,
                "max_volume_bytes": 1000,
                "measurement_window_seconds": 30,
            }
        )
        self.write_scope(invalid_limits)
        with self.assertRaises(ScopeValidationError):
            self.validate()

    def test_rejects_targets_outside_strict_allowlist_and_wildcards(self) -> None:
        self.write_scope(scope_document())
        with self.assertRaisesRegex(ScopeValidationError, "allowlist"):
            self.validate(targets=["api.example.test.evil"])

        self.write_scope(scope_document(allowed_targets=["*"]))
        with self.assertRaises(ScopeValidationError):
            self.validate()

    def test_rejects_unauthorized_modules_and_empty_requests(self) -> None:
        self.write_scope(scope_document())
        with self.assertRaisesRegex(ScopeValidationError, "não autorizados"):
            self.validate(modules=["inventory", "admin"])
        with self.assertRaises(ScopeValidationError):
            self.validate(targets=[])
        with self.assertRaises(ScopeValidationError):
            self.validate(modules=[])

    def test_duplicate_json_keys_are_rejected(self) -> None:
        self.scope_path.write_text(
            '{"engagement_id":"one","engagement_id":"two"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(ScopeValidationError, "duplicada"):
            self.validate()


class ScopeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.scope_path = Path(self.temp_dir.name) / "scope.json"
        self.scope_path.write_text(json.dumps(scope_document()), encoding="utf-8")
        self.orchestrator = CoreOrchestrator(clock=lambda: NOW)
        self.run = self.orchestrator.create_run("test")

    def validate(self, path: str | Path | None = None, **overrides: object):
        arguments: dict[str, object] = {
            "engagement_id": "engagement-1",
            "environment": "staging",
            "targets": ["api.example.test"],
            "modules": ["inventory"],
            "validator": ScopeValidator(clock=lambda: NOW),
        }
        arguments.update(overrides)
        return self.orchestrator.validate_scope(
            self.run.run_id, str(path or self.scope_path), **arguments  # type: ignore[arg-type]
        )

    def test_execution_is_blocked_without_scope_or_after_scope_failure(self) -> None:
        with self.assertRaises(ScopeValidationError):
            self.validate(self.scope_path.with_name("missing.json"))

        self.assertTrue(self.orchestrator.kill_switch.is_triggered)
        self.assertEqual(
            self.orchestrator.get_state(self.run.run_id), RunState.BLOCKED
        )
        with self.assertRaises(KillSwitchTriggered):
            self.orchestrator.create_run("test")

    def test_attempt_to_run_without_validated_scope_trips_switch(self) -> None:
        with self.assertRaises(ScopeValidationError):
            self.orchestrator.transition(self.run.run_id, RunState.READY)

        self.assertTrue(self.orchestrator.kill_switch.is_triggered)
        self.assertEqual(
            self.orchestrator.get_state(self.run.run_id), RunState.BLOCKED
        )

    def test_validated_scope_is_required_before_running(self) -> None:
        self.validate()
        self.assertEqual(self.orchestrator.get_state(self.run.run_id), RunState.READY)
        self.orchestrator.transition(self.run.run_id, RunState.RUNNING)
        self.assertEqual(self.orchestrator.get_state(self.run.run_id), RunState.RUNNING)
        self.assertIsNotNone(self.orchestrator.get_operational_limits(self.run.run_id))

    def test_scope_failure_stops_other_active_runs(self) -> None:
        valid_run = self.orchestrator.create_run("test")
        self.orchestrator.validate_scope(
            valid_run.run_id,
            str(self.scope_path),
            engagement_id="engagement-1",
            environment="staging",
            targets=["api.example.test"],
            modules=["inventory"],
            validator=ScopeValidator(clock=lambda: NOW),
        )
        self.orchestrator.transition(valid_run.run_id, RunState.RUNNING)

        with self.assertRaises(ScopeValidationError):
            self.validate(modules=["unauthorized"])

        self.assertEqual(
            self.orchestrator.get_state(self.run.run_id), RunState.BLOCKED
        )
        self.assertEqual(
            self.orchestrator.get_state(valid_run.run_id), RunState.STOPPED
        )

    def test_operational_breach_stops_active_run_via_central_switch(self) -> None:
        self.validate()
        self.orchestrator.transition(self.run.run_id, RunState.RUNNING)
        enforcer = self.orchestrator.get_operational_limits(self.run.run_id)

        with enforcer.begin_operation():
            with self.assertRaises(OperationalLimitExceeded):
                enforcer.record_result(
                    rtt_ms=1501,
                    status_code=200,
                    volume_bytes=0,
                )

        self.assertTrue(self.orchestrator.kill_switch.is_triggered)
        self.assertEqual(
            self.orchestrator.get_state(self.run.run_id), RunState.STOPPED
        )

    def _create_short_lived_run(self):
        clock_value = [NOW]
        clock = lambda: clock_value[0]
        orchestrator = CoreOrchestrator(clock=clock)
        run = orchestrator.create_run("test")
        document = scope_document(
            valid_until_utc=(NOW + timedelta(seconds=5)).isoformat()
        )
        self.scope_path.write_text(json.dumps(document), encoding="utf-8")
        orchestrator.validate_scope(
            run.run_id,
            str(self.scope_path),
            engagement_id="engagement-1",
            environment="staging",
            targets=["api.example.test"],
            modules=["inventory"],
            validator=ScopeValidator(
                clock=clock,
                kill_switch=orchestrator.kill_switch,
            ),
        )
        return orchestrator, run, clock_value

    def test_expired_scope_blocks_transition_to_running(self) -> None:
        orchestrator, run, clock_value = self._create_short_lived_run()
        clock_value[0] += timedelta(seconds=6)

        with self.assertRaisesRegex(OperationalLimitExceeded, "expirou"):
            orchestrator.transition(run.run_id, RunState.RUNNING)

        self.assertTrue(orchestrator.kill_switch.is_triggered)
        self.assertEqual(orchestrator.get_state(run.run_id), RunState.STOPPED)
        safety_events = [
            event for event in orchestrator.events.history
            if event.name == "safety.triggered"
        ]
        self.assertEqual(safety_events[-1].payload["reason_code"], "scope_expired")

    def test_expired_scope_stops_running_operation_and_module_record(self) -> None:
        orchestrator, run, clock_value = self._create_short_lived_run()
        orchestrator.transition(run.run_id, RunState.RUNNING)
        clock_value[0] += timedelta(seconds=6)
        enforcer = orchestrator.get_operational_limits(run.run_id)

        with self.assertRaisesRegex(OperationalLimitExceeded, "expirou"):
            enforcer.begin_operation()

        self.assertTrue(orchestrator.kill_switch.is_triggered)
        self.assertEqual(orchestrator.get_state(run.run_id), RunState.STOPPED)

    def test_expiry_during_operation_trips_on_operation_exit(self) -> None:
        orchestrator, run, clock_value = self._create_short_lived_run()
        orchestrator.transition(run.run_id, RunState.RUNNING)
        enforcer = orchestrator.get_operational_limits(run.run_id)

        with self.assertRaisesRegex(OperationalLimitExceeded, "expirou"):
            with enforcer.begin_operation():
                clock_value[0] += timedelta(seconds=6)

        self.assertEqual(enforcer.active_operations, 0)
        self.assertEqual(orchestrator.get_state(run.run_id), RunState.STOPPED)

    def test_expired_scope_is_checked_before_module_execution_is_recorded(self) -> None:
        orchestrator, run, clock_value = self._create_short_lived_run()
        orchestrator.transition(run.run_id, RunState.RUNNING)
        clock_value[0] += timedelta(seconds=6)

        with self.assertRaisesRegex(OperationalLimitExceeded, "expirou"):
            orchestrator.record_module_execution(run.run_id, "inventory")

        self.assertEqual(orchestrator.get_state(run.run_id), RunState.STOPPED)


class OperationalLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.time = [NOW]
        self.kill_switch = KillSwitch()
        self.limits = ScopeLimits(
            max_duration_seconds=60,
            max_rate_per_second=10,
            max_concurrency=2,
            max_volume_bytes=1000,
            measurement_window_seconds=10,
        )
        self.enforcer = OperationalLimitEnforcer(
            RunContext.create("test").run_id,
            self.limits,
            self.kill_switch,
            clock=lambda: self.time[0],
        )
        self.enforcer.start()

    def result(self, *, rtt_ms: int = 100, status_code: int = 200, volume: int = 0):
        with self.enforcer.begin_operation():
            self.enforcer.record_result(
                rtt_ms=rtt_ms,
                status_code=status_code,
                volume_bytes=volume,
            )

    def test_rtt_over_1500_ms_trips_central_kill_switch(self) -> None:
        with self.assertRaisesRegex(OperationalLimitExceeded, "RTT"):
            self.result(rtt_ms=1501)
        self.assertTrue(self.kill_switch.is_triggered)

    def test_5xx_ratio_over_five_percent_trips_after_ten_samples(self) -> None:
        for _ in range(9):
            self.result()

        with self.assertRaisesRegex(OperationalLimitExceeded, "5xx"):
            self.result(status_code=500)
        self.assertTrue(self.kill_switch.is_triggered)

    def test_volume_cap_is_enforced_in_bytes(self) -> None:
        self.result(volume=1000)
        with self.assertRaisesRegex(OperationalLimitExceeded, "volume"):
            self.result(volume=1)

    def test_concurrency_cap_is_enforced(self) -> None:
        limited = OperationalLimitEnforcer(
            RunContext.create("test").run_id,
            ScopeLimits(60, 10, 1, 1000, 10),
            KillSwitch(),
            clock=lambda: self.time[0],
        )
        limited.start()
        first = limited.begin_operation()
        with self.assertRaisesRegex(OperationalLimitExceeded, "concorrência"):
            limited.begin_operation()
        first.close()

    def test_rate_cap_uses_configured_rolling_window(self) -> None:
        limited = OperationalLimitEnforcer(
            RunContext.create("test").run_id,
            ScopeLimits(60, 1, 10, 1000, 2),
            KillSwitch(),
            clock=lambda: self.time[0],
        )
        limited.start()
        for _ in range(2):
            with limited.begin_operation():
                pass
        with self.assertRaisesRegex(OperationalLimitExceeded, "taxa"):
            limited.begin_operation()

    def test_duration_cap_is_enforced(self) -> None:
        self.time[0] += timedelta(seconds=61)
        with self.assertRaisesRegex(OperationalLimitExceeded, "duração"):
            self.enforcer.check_duration()

    def test_measurements_are_rejected_after_kill_switch(self) -> None:
        self.kill_switch.trigger("test stop")
        with self.assertRaises(KillSwitchTriggered):
            self.enforcer.begin_operation()


if __name__ == "__main__":
    unittest.main()
