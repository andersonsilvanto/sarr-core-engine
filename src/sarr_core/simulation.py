"""Application-level facade for the bounded localhost telemetry simulation."""

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from uuid import UUID

from core import (
    CoreOrchestrator,
    LocalDemoServer,
    LocalTelemetryProbe,
    Persistence,
    RunState,
    ScopeValidator,
    TelemetrySample,
    TelemetryScenario,
    resolve_data_directory,
)


@dataclass(frozen=True)
class SimulationSnapshot:
    run_id: UUID
    state: RunState
    telemetry: TelemetrySample | None


class LocalSimulationSession:
    """Owns simulation lifecycle and exposes a UI-safe, read-only snapshot."""

    def __init__(self) -> None:
        self.data_directory = resolve_data_directory()
        self._persistence = Persistence(
            self.data_directory / "sarr-core.sqlite3",
            self.data_directory / "audit.jsonl",
        )
        self._orchestrator = CoreOrchestrator(persistence=self._persistence)
        self._run = self._orchestrator.create_run("simulation")
        self._lock = RLock()
        self._started = False
        self._closed = False
        self._telemetry: TelemetrySample | None = None

    @property
    def snapshot(self) -> SimulationSnapshot:
        with self._lock:
            telemetry = self._telemetry
        return SimulationSnapshot(
            run_id=self._run.run_id,
            state=self._orchestrator.get_state(self._run.run_id),
            telemetry=telemetry,
        )

    def run(self) -> SimulationSnapshot:
        with self._lock:
            if self._closed:
                raise RuntimeError("Simulation session is closed.")
            if self._started:
                raise RuntimeError("Simulation session can only run once.")
            self._started = True

        try:
            self._validate_local_scope()
            self._orchestrator.transition(self._run.run_id, RunState.RUNNING)
            with LocalDemoServer(
                TelemetryScenario.NORMAL_LATENCY,
                max_requests=1,
            ) as server:
                probe = LocalTelemetryProbe(
                    port=server.port,
                    run_id=self._run.run_id,
                    limits=self._orchestrator.get_operational_limits(
                        self._run.run_id
                    ),
                    kill_switch=self._orchestrator.kill_switch,
                    event_bus=self._orchestrator.events,
                )
                sample = probe.sample()
            with self._lock:
                self._telemetry = sample
            self._orchestrator.record_module_execution(
                self._run.run_id,
                "telemetry_demo",
            )
            self._orchestrator.transition(self._run.run_id, RunState.COMPLETED)
            return self.snapshot
        finally:
            self.close()

    def stop(self) -> None:
        snapshot = self.snapshot
        if snapshot.state not in (
            RunState.STOPPED,
            RunState.FAILED,
            RunState.COMPLETED,
            RunState.BLOCKED,
        ):
            self._orchestrator.kill_switch.trigger(
                "Manual interruption requested from local dashboard.",
                reason_code="manual_interruption",
                run_id=self._run.run_id,
                blocked_run_id=self._run.run_id,
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._persistence.close()

    def event_log(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (
                event.timestamp_utc.isoformat().replace("+00:00", "Z"),
                event.name,
            )
            for event in self._orchestrator.events.history
        )

    def _validate_local_scope(self) -> None:
        now = datetime.now(timezone.utc)
        scope_document = {
            "engagement_id": "local-gui-demo",
            "environment": "local",
            "mode": "simulation",
            "valid_from_utc": (now - timedelta(seconds=1)).isoformat(),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat(),
            "allowed_targets": ["127.0.0.1"],
            "allowed_modules": ["telemetry_demo"],
            "limits": {
                "max_duration_seconds": 60,
                "max_rate_per_second": 2,
                "max_concurrency": 1,
                "max_volume_bytes": 16_384,
                "measurement_window_seconds": 10,
            },
        }
        with tempfile.TemporaryDirectory(prefix="sarr-core-gui-") as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(
                json.dumps(scope_document),
                encoding="utf-8",
            )
            self._orchestrator.validate_scope(
                self._run.run_id,
                str(scope_path),
                engagement_id="local-gui-demo",
                environment="local",
                targets=["127.0.0.1"],
                modules=["telemetry_demo"],
                validator=ScopeValidator(
                    kill_switch=self._orchestrator.kill_switch,
                ),
            )
