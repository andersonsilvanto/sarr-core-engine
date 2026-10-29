"""Local smoke tests for the SARR-Core safety gates."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import (
    CoreOrchestrator,
    InvalidStateTransitionError,
    KillSwitch,
    OperationalLimitEnforcer,
    OperationalLimitExceeded,
    RunContext,
    RunState,
    RunStateMachine,
    ScopeLimits,
    ScopeValidationError,
    ScopeValidator,
)


NOW = datetime(2026, 10, 29, 15, 0, tzinfo=timezone.utc)


def _scope_document(*, valid_until: datetime) -> dict[str, object]:
    return {
        "engagement_id": "TEST-SMOKE-01",
        "environment": "local-lab",
        "mode": "simulation",
        "valid_from_utc": (NOW - timedelta(minutes=5)).isoformat(),
        "valid_until_utc": valid_until.isoformat(),
        "allowed_targets": ["127.0.0.1"],
        "allowed_modules": ["telemetry_demo"],
        "limits": {
            "max_duration_seconds": 60,
            "max_rate_per_second": 10,
            "max_concurrency": 1,
            "max_volume_bytes": 4096,
            "measurement_window_seconds": 10,
        },
    }


def _validate(validator: ScopeValidator, scope_path: Path):
    return validator.validate(
        scope_path,
        engagement_id="TEST-SMOKE-01",
        environment="local-lab",
        mode="simulation",
        targets=["127.0.0.1"],
        modules=["telemetry_demo"],
    )


def _make_enforcer():
    switch = KillSwitch()
    limits = OperationalLimitEnforcer(
        RunContext.create("simulation").run_id,
        ScopeLimits(
            max_duration_seconds=60,
            max_rate_per_second=10,
            max_concurrency=1,
            max_volume_bytes=4096,
            measurement_window_seconds=10,
        ),
        switch,
        clock=lambda: NOW,
    )
    limits.start()
    return switch, limits


class SmokeTests(unittest.TestCase):
    def test_environment_and_imports(self) -> None:
        """ST-01: Valida instanciação limpa do Core."""
        engine = CoreOrchestrator()
        run = engine.create_run("simulation")
        self.assertIsNotNone(run)
        self.assertEqual(engine.get_state(run.run_id), RunState.IDLE)

    def test_state_machine_invalid_transition(self) -> None:
        """ST-02: Rejeita transições inválidas na máquina de estados."""
        machine = RunStateMachine(RunContext.create("simulation"))
        with self.assertRaises(InvalidStateTransitionError):
            machine.transition_to(RunState.RUNNING)
        self.assertEqual(machine.state, RunState.IDLE)

    def test_scope_validator_missing_file_fails_closed(self) -> None:
        """ST-03: Aplica fail-closed para escopo ausente."""
        with tempfile.TemporaryDirectory() as temporary:
            missing_path = Path(temporary) / "non_existent_scope.json"
            validator = ScopeValidator(clock=lambda: NOW)

            with self.assertRaisesRegex(ScopeValidationError, "ausente"):
                _validate(validator, missing_path)

    def test_scope_validator_rejects_expired_scope(self) -> None:
        """ST-03: Bloqueia escopo expirado."""
        with tempfile.TemporaryDirectory() as temporary:
            scope_path = Path(temporary) / "expired_scope.json"
            scope_path.write_text(
                json.dumps(_scope_document(valid_until=NOW - timedelta(seconds=1))),
                encoding="utf-8",
            )
            validator = ScopeValidator(clock=lambda: NOW)

            with self.assertRaisesRegex(ScopeValidationError, "expirado"):
                _validate(validator, scope_path)

    def test_kill_switch_rtt_threshold(self) -> None:
        """ST-04: Dispara kill-switch com RTT > 1500ms."""
        switch, limits = _make_enforcer()
        with self.assertRaisesRegex(OperationalLimitExceeded, "RTT"):
            with limits.begin_operation():
                limits.record_result(
                    rtt_ms=1501,
                    status_code=200,
                    volume_bytes=0,
                )

        self.assertTrue(switch.is_triggered)
        self.assertEqual(switch.event.reason_code, "rtt_limit")

    def test_kill_switch_error_rate_threshold(self) -> None:
        """ST-04: Dispara kill-switch quando a taxa 5xx excede 5%."""
        switch, limits = _make_enforcer()
        for _ in range(9):
            with limits.begin_operation():
                limits.record_result(
                    rtt_ms=200,
                    status_code=200,
                    volume_bytes=0,
                )

        with self.assertRaisesRegex(OperationalLimitExceeded, "5xx"):
            with limits.begin_operation():
                limits.record_result(
                    rtt_ms=200,
                    status_code=500,
                    volume_bytes=0,
                )

        self.assertTrue(switch.is_triggered)
        self.assertEqual(switch.event.reason_code, "http_5xx_limit")


if __name__ == "__main__":
    unittest.main()
