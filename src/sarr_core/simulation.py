"""Offline security-audit scenarios using synthetic or project-local evidence."""

import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from uuid import UUID

from core import (
    CoreOrchestrator,
    Persistence,
    RunState,
    ScopeValidator,
    resolve_data_directory,
)
from core.events import Event
from core.security_audit import (
    IntegrityEvidence,
    PortEvidence,
    SecurityAudit,
    SecurityFinding,
)


_SCHEMA_BASELINES = {
    "schemas/dashboard.schema.json": "699a4e898bce011696176992b3d4984256990b4fe3b3f25975ebdd3b2cde51a2",
    "schemas/scope.schema.json": "0a22a28baae7ebc583ac4928a68e3eee88607b11aa6a630243b14e5d5f2b8c65",
}


def _resolve_project_root() -> Path:
    source_root = Path(__file__).resolve().parents[2]
    installed_root = Path(sys.prefix)
    for candidate in (source_root, installed_root):
        if all(
            (candidate / relative_path).is_file()
            for relative_path in _SCHEMA_BASELINES
        ):
            return candidate
    return source_root


class SecurityScenario(str, Enum):
    NORMAL = "normal"
    UNAUTHORIZED_PORT = "unauthorized-port"
    INTEGRITY_MISMATCH = "integrity-mismatch"
    BRUTE_FORCE = "brute-force"
    MANUAL_INTERRUPTION = "manual-interruption"


@dataclass(frozen=True)
class SimulationSnapshot:
    run_id: UUID
    state: RunState
    findings: tuple[SecurityFinding, ...]


class LocalSimulationSession:
    """Runs a one-shot, network-free security audit scenario."""

    def __init__(
        self,
        scenario: SecurityScenario = SecurityScenario.NORMAL,
    ) -> None:
        if not isinstance(scenario, SecurityScenario):
            try:
                scenario = SecurityScenario(scenario)
            except (TypeError, ValueError) as error:
                raise ValueError(f"Unsupported security scenario: {scenario!r}") from error
        self._scenario = scenario
        self._project_root = _resolve_project_root()
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
        self._findings: tuple[SecurityFinding, ...] = ()

    @property
    def snapshot(self) -> SimulationSnapshot:
        with self._lock:
            findings = self._findings
        return SimulationSnapshot(
            run_id=self._run.run_id,
            state=self._orchestrator.get_state(self._run.run_id),
            findings=findings,
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
            if self._scenario is SecurityScenario.MANUAL_INTERRUPTION:
                self.stop()
                return self.snapshot

            ports, integrity, permission_paths, auth_failures = self._scenario_evidence()
            audit = SecurityAudit(
                run_id=self._run.run_id,
                event_bus=self._orchestrator.events,
                kill_switch=self._orchestrator.kill_switch,
                project_root=self._project_root,
            )
            findings = audit.run(
                ports=ports,
                integrity=integrity,
                permission_paths=permission_paths,
                simulated_auth_failures=auth_failures,
            )
            with self._lock:
                self._findings = findings
            for finding in findings:
                self._persist_finding(finding)

            if not self._orchestrator.kill_switch.is_triggered:
                self._orchestrator.record_module_execution(
                    self._run.run_id,
                    "security_audit_demo",
                )
                self._orchestrator.transition(self._run.run_id, RunState.COMPLETED)
            return self.snapshot
        except Exception:
            if not self._orchestrator.kill_switch.is_triggered:
                self._orchestrator.kill_switch.trigger(
                    "Security audit execution failed.",
                    reason_code="security_audit_failed",
                    run_id=self._run.run_id,
                    blocked_run_id=self._run.run_id,
                )
            raise
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

    def _scenario_evidence(
        self,
    ) -> tuple[
        tuple[PortEvidence, ...],
        tuple[IntegrityEvidence, ...],
        tuple[Path, ...],
        int,
    ]:
        ports = (
            PortEvidence(
                host="127.0.0.1",
                port=8500,
                service="synthetic-demo-service",
                authorized=True,
            ),
        )
        if self._scenario is SecurityScenario.UNAUTHORIZED_PORT:
            ports = (
                PortEvidence(
                    host="127.0.0.1",
                    port=22,
                    service="synthetic-ssh-fixture",
                    authorized=False,
                ),
            )

        integrity: list[IntegrityEvidence] = []
        for relative_path, expected_hash in _SCHEMA_BASELINES.items():
            if (
                self._scenario is SecurityScenario.INTEGRITY_MISMATCH
                and relative_path == "schemas/scope.schema.json"
            ):
                expected_hash = "0" * 64
            integrity.append(
                IntegrityEvidence(
                    path=self._project_root / relative_path,
                    expected_sha256=expected_hash,
                )
            )

        return (
            ports,
            tuple(integrity),
            tuple(self._project_root / name for name in _SCHEMA_BASELINES),
            10 if self._scenario is SecurityScenario.BRUTE_FORCE else 0,
        )

    def _persist_finding(self, finding: SecurityFinding) -> None:
        persistence = self._orchestrator.persistence
        if persistence is None:
            raise RuntimeError("Security findings require configured persistence.")
        record = persistence.findings.create(
            self._run.run_id,
            severity=finding.severity,
            title=finding.event_name,
            description=finding.summary,
            details=finding.evidence,
        )
        self._orchestrator.events.publish(
            Event(
                run_id=self._run.run_id,
                name="finding.created",
                payload={
                    "finding_id": str(record.finding_id),
                    "severity": record.severity,
                },
            )
        )

    def _validate_local_scope(self) -> None:
        now = datetime.now(timezone.utc)
        scope_document = {
            "engagement_id": "local-security-demo",
            "environment": "local",
            "mode": "simulation",
            "valid_from_utc": (now - timedelta(seconds=1)).isoformat(),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat(),
            "allowed_targets": ["127.0.0.1"],
            "allowed_modules": ["security_audit_demo"],
            "limits": {
                "max_duration_seconds": 60,
                "max_rate_per_second": 2,
                "max_concurrency": 1,
                "max_volume_bytes": 16_384,
                "measurement_window_seconds": 10,
            },
        }
        with tempfile.TemporaryDirectory(prefix="sarr-core-security-") as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(
                json.dumps(scope_document),
                encoding="utf-8",
            )
            self._orchestrator.validate_scope(
                self._run.run_id,
                str(scope_path),
                engagement_id="local-security-demo",
                environment="local",
                targets=["127.0.0.1"],
                modules=["security_audit_demo"],
                validator=ScopeValidator(
                    kill_switch=self._orchestrator.kill_switch,
                ),
            )


__all__ = [
    "LocalSimulationSession",
    "SecurityScenario",
    "SimulationSnapshot",
]
