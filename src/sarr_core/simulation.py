"""Offline security-audit scenarios using synthetic or project-local evidence."""

import hashlib
import json
import os
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
from core.report_service import AuditReportService
from core.security_audit import (
    GhostPortAttempt,
    IntegrityEvidence,
    PersistenceEvidence,
    PermissionEvidence,
    PortEvidence,
    SecurityAudit,
    SecurityFinding,
)
from sarr_core.external_scanners import ExternalScannerManager


_FILE_BASELINES = {
    "config/dashboard.schema.json": "d92ec42429b3040fa8d6c6ace0c780b03a8e29a542a45864fd13c2150d2dbb1d",
    "config/network_detection.json": "206bd6a36ac15a2f3c0f2a636c986c61ab956aef1688805ad9f55ffe1999dd77",
    "schemas/dashboard.schema.json": "cb365b4e840274535eed412f0f964cc40dbe73415b46531b2aeea3e3d01ecf83",
    "schemas/network_detection.schema.json": "9789518c69196f15ae399c3201e2d623f23416f8a0851d8a60d7e1e708c8b0ba",
    "schemas/scope.schema.json": "b2f3aad232639b1cb426ecdc5e8af20d4f903f630abc3e68d3c93460bc53d82a",
    "config/canary_credentials.json": "0e0327a52fce728467937890299c8ae121e19b398c1855445323c6056e3ec9a6",
}
_REPAIRABLE_BASELINES = {
    "config/dashboard.schema.json": (
        "schemas/dashboard.schema.json",
        _FILE_BASELINES["config/dashboard.schema.json"],
    ),
}


def hardening_score(findings: tuple[SecurityFinding, ...]) -> int:
    """Return a conservative 0-100 score based on unresolved audit findings."""
    penalty_by_severity = {
        "critical": 25,
        "high": 15,
        "medium": 10,
        "warning": 5,
        "low": 2,
        "info": 0,
    }
    penalty = sum(
        penalty_by_severity.get(finding.severity.lower(), 10)
        for finding in findings
    )
    return max(0, 100 - penalty)


def restore_known_baselines(
    project_root: str | Path | None = None,
) -> tuple[Path, ...]:
    """Restore only explicitly repairable files from verified project baselines."""
    root = (
        Path(project_root).resolve()
        if project_root is not None
        else _resolve_project_root()
    )
    restored: list[Path] = []
    for target_relative, (source_relative, expected_hash) in (
        _REPAIRABLE_BASELINES.items()
    ):
        for relative_path in (source_relative, target_relative):
            candidate = root
            for component in Path(relative_path).parts:
                candidate = candidate / component
                if candidate.is_symlink():
                    raise RuntimeError(
                        f"Refusing baseline repair through a symlink: {relative_path}"
                    )
        source = (root / source_relative).resolve()
        target = (root / target_relative).resolve()
        try:
            source.relative_to(root)
            target.relative_to(root)
        except ValueError as error:
            raise ValueError("Baseline paths must remain inside project root.") from error

        source_bytes = source.read_bytes()
        if hashlib.sha256(source_bytes).hexdigest() != _FILE_BASELINES[source_relative]:
            raise RuntimeError(
                f"Trusted source baseline failed verification: {source_relative}"
            )
        document = json.loads(source_bytes.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError(f"Baseline JSON must be an object: {source_relative}")
        restored_bytes = (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if hashlib.sha256(restored_bytes).hexdigest() != expected_hash:
            raise RuntimeError(
                f"Restored content does not match approved baseline: {target_relative}"
            )
        if target.is_file() and target.read_bytes() == restored_bytes:
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(restored_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash:
            raise RuntimeError(
                f"Restored file failed post-write verification: {target_relative}"
            )
        restored.append(target)
    return tuple(restored)


def _resolve_project_root() -> Path:
    source_root = Path(__file__).resolve().parents[2]
    installed_root = Path(sys.prefix)
    for candidate in (source_root, installed_root):
        if all(
            (candidate / relative_path).is_file()
            for relative_path in _FILE_BASELINES
        ):
            return candidate
    return source_root


class SecurityScenario(str, Enum):
    NORMAL = "normal"
    UNAUTHORIZED_PORT = "unauthorized-port"
    INTEGRITY_MISMATCH = "integrity-mismatch"
    BRUTE_FORCE = "brute-force"
    MANUAL_INTERRUPTION = "manual-interruption"
    PORTA_DESPROTEGIDA = "porta_desprotegida"
    PERMISSAO_FROUXA = "permissao_frouxa"
    HASH_ADULTERADO = "hash_adulterado"
    OBFUSCATION = "obfuscation"
    PERSISTENCE = "persistence"
    CANARY_ACCESS = "canary-access"
    GHOST_PORT = "ghost-port"


@dataclass(frozen=True)
class SimulationSnapshot:
    run_id: UUID
    state: RunState
    findings: tuple[SecurityFinding, ...]
    healed_paths: tuple[str, ...] = ()
    scanner_status: tuple[tuple[str, str], ...] = ()

    @property
    def hardening_score(self) -> int:
        return hardening_score(self.findings)


class LocalSimulationSession:
    """Runs a one-shot, network-free security audit scenario."""

    def __init__(
        self,
        scenario: SecurityScenario = SecurityScenario.NORMAL,
        *,
        tshark_capture: str | Path | None = None,
    ) -> None:
        if not isinstance(scenario, SecurityScenario):
            try:
                scenario = SecurityScenario(scenario)
            except (TypeError, ValueError) as error:
                raise ValueError(f"Unsupported security scenario: {scenario!r}") from error
        self._scenario = scenario
        self._project_root = _resolve_project_root()
        self._tshark_capture = tshark_capture
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
        self._executive_report: dict[str, object] | None = None
        self._healed_paths: tuple[str, ...] = ()
        self._scanner_status: tuple[tuple[str, str], ...] = ()
        self._shadow_baselines = self._load_shadow_baselines()

    @property
    def snapshot(self) -> SimulationSnapshot:
        with self._lock:
            findings = self._findings
        return SimulationSnapshot(
            run_id=self._run.run_id,
            state=self._orchestrator.get_state(self._run.run_id),
            findings=findings,
            healed_paths=self._healed_paths,
            scanner_status=self._scanner_status,
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
                self._capture_executive_report()
                return self.snapshot

            self._healed_paths = self._heal_shadow_baselines()
            (
                ports,
                integrity,
                permission_paths,
                permission_fixtures,
                auth_failures,
                encoded_payload_samples,
                simulated_subprocess_commands,
                persistence_fixtures,
                canary_accessed,
                ghost_port_attempts,
            ) = self._scenario_evidence()
            scanner_result = ExternalScannerManager(
                self._project_root
            ).run_local_checks(offline_capture=self._tshark_capture)
            self._scanner_status = scanner_result.statuses
            for tool, status in scanner_result.statuses:
                self._orchestrator.events.publish(
                    Event(
                        run_id=self._run.run_id,
                        name="external.scanner.status",
                        payload={"tool": tool, "status": status},
                    )
                )
            for finding in scanner_result.findings:
                self._orchestrator.events.publish(
                    Event(
                        run_id=self._run.run_id,
                        name=finding.event_name,
                        payload={
                            **finding.evidence,
                            "severity": finding.severity,
                            "summary": finding.summary,
                            "vetor_ataque": finding.vetor_ataque,
                            "remediacao": finding.remediacao,
                            "mitre_id": finding.mitre_id,
                            "acao_bloqueio": finding.acao_bloqueio,
                        },
                    )
                )
                if finding.event_name == "network.correlation.vulnerability_detected":
                    self._orchestrator.kill_switch.trigger(
                        finding.summary,
                        reason_code="network_correlation_critical",
                        run_id=self._run.run_id,
                        blocked_run_id=self._run.run_id,
                    )
            discovered_files = self._discover_local_files()
            self._publish_atomic_tactic(
                "T1083",
                "file_directory_discovery",
                len(discovered_files),
                "project-local config/ and schemas/ inventory",
            )
            self._publish_atomic_tactic(
                "T1046",
                "network_service_discovery",
                len(ports),
                "loopback inventory fixture; no sockets opened",
            )
            self._publish_atomic_tactic(
                "T1222",
                "file_permissions_audit",
                len(permission_paths) + len(permission_fixtures),
                "read-only ACL/mode inspection or synthetic fixture",
            )
            if encoded_payload_samples or simulated_subprocess_commands:
                self._publish_atomic_tactic(
                    "T1027",
                    "synthetic_obfuscation_detection",
                    len(encoded_payload_samples) + len(simulated_subprocess_commands),
                    "static synthetic indicators; no payload or subprocess executed",
                )
            for evidence in persistence_fixtures:
                mitre_id = (
                    "T1053.005"
                    if evidence.mechanism == "scheduled_task"
                    else "T1547.001"
                )
                self._publish_atomic_tactic(
                    mitre_id,
                    "synthetic_persistence_audit",
                    1,
                    "synthetic fixture only; no operating-system persistence queried",
                )
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
                permission_fixtures=permission_fixtures,
                simulated_auth_failures=auth_failures,
                encoded_payload_samples=encoded_payload_samples,
                simulated_subprocess_commands=simulated_subprocess_commands,
                persistence_fixtures=persistence_fixtures,
                canary_accessed=canary_accessed,
                ghost_port_attempts=ghost_port_attempts,
            )
            findings = (*findings, *scanner_result.findings)
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
            self._capture_executive_report()
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

    @property
    def has_executive_report(self) -> bool:
        return self._executive_report is not None

    def export_executive_report(
        self,
        destination: str | Path,
        *,
        format: str,
    ) -> Path:
        report = self._executive_report
        if report is None:
            raise RuntimeError("An execution report is available only after a completed audit.")
        if format == "json":
            return AuditReportService.export_json(report, destination)
        if format == "markdown":
            return AuditReportService.export_markdown(report, destination)
        raise ValueError("Report format must be 'json' or 'markdown'.")

    def _capture_executive_report(self) -> None:
        self._executive_report = AuditReportService(self._orchestrator).build_report(
            self._run.run_id,
            operator="local-operator",
        )

    def _load_shadow_baselines(self) -> dict[str, bytes]:
        shadow: dict[str, bytes] = {}
        for relative_path, expected_sha256 in _FILE_BASELINES.items():
            path = self._project_root / relative_path
            if self._has_symlink_component(path):
                continue
            try:
                content = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(content).hexdigest() == expected_sha256:
                shadow[relative_path] = content
        return shadow

    def _heal_shadow_baselines(self) -> tuple[str, ...]:
        healed: list[str] = []
        for relative_path, shadow_content in self._shadow_baselines.items():
            path = self._project_root / relative_path
            if self._has_symlink_component(path):
                raise RuntimeError(
                    f"Refusing automatic healing through a symlink: {relative_path}"
                )
            try:
                current_content = path.read_bytes()
            except FileNotFoundError:
                current_content = None
            except OSError as error:
                raise RuntimeError(
                    f"Could not inspect baseline file {relative_path}."
                ) from error
            expected_sha256 = _FILE_BASELINES[relative_path]
            if (
                current_content is not None
                and hashlib.sha256(current_content).hexdigest() == expected_sha256
            ):
                continue

            path.parent.mkdir(parents=True, exist_ok=True)
            if self._has_symlink_component(path):
                raise RuntimeError(
                    f"Refusing automatic healing through a symlink: {relative_path}"
                )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".heal",
                dir=path.parent,
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(shadow_content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, path)
                temporary_path = None
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)

            actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_sha256 != expected_sha256:
                raise RuntimeError(
                    f"Automatic healing verification failed for {relative_path}."
                )
            self._orchestrator.events.publish(
                Event(
                    run_id=self._run.run_id,
                    name="security.state.healed",
                    payload={
                        "path": relative_path,
                        "sha256": actual_sha256,
                        "status": "RESTORED / HEALED",
                        "source": "verified_in_memory_shadow_baseline",
                    },
                )
            )
            healed.append(relative_path)
        return tuple(healed)

    def _has_symlink_component(self, path: Path) -> bool:
        candidate = self._project_root
        try:
            relative = path.absolute().relative_to(self._project_root)
        except ValueError:
            return True
        for component in relative.parts:
            candidate = candidate / component
            if candidate.is_symlink():
                return True
        return False

    def _scenario_evidence(
        self,
    ) -> tuple[
        tuple[PortEvidence, ...],
        tuple[IntegrityEvidence, ...],
        tuple[Path, ...],
        tuple[PermissionEvidence, ...],
        int,
        tuple[str, ...],
        tuple[str, ...],
        tuple[PersistenceEvidence, ...],
        bool,
        tuple[GhostPortAttempt, ...],
    ]:
        ports = (
            PortEvidence(
                host="127.0.0.1",
                port=8500,
                service="synthetic-demo-service",
                authorized=True,
            ),
        )
        if self._scenario in (
            SecurityScenario.UNAUTHORIZED_PORT,
            SecurityScenario.PORTA_DESPROTEGIDA,
        ):
            port = (
                8080
                if self._scenario is SecurityScenario.PORTA_DESPROTEGIDA
                else 22
            )
            ports = (
                PortEvidence(
                    host="127.0.0.1",
                    port=port,
                    service=(
                        "synthetic-http-without-auth"
                        if port == 8080
                        else "synthetic-ssh-fixture"
                    ),
                    authorized=False,
                    authentication=(
                        "absent" if port == 8080 else "unknown"
                    ),
                ),
            )

        integrity_mismatch = self._scenario in (
            SecurityScenario.INTEGRITY_MISMATCH,
            SecurityScenario.HASH_ADULTERADO,
        )
        integrity: list[IntegrityEvidence] = []
        for relative_path, expected_hash in _FILE_BASELINES.items():
            if (
                integrity_mismatch
                and relative_path == "schemas/scope.schema.json"
            ):
                expected_hash = "0" * 64
            integrity.append(
                IntegrityEvidence(
                    path=self._project_root / relative_path,
                    expected_sha256=expected_hash,
                )
            )
        known_paths = {
            (self._project_root / relative_path).resolve()
            for relative_path in _FILE_BASELINES
        }
        for path in self._discover_local_files():
            resolved_path = path.resolve()
            if resolved_path not in known_paths:
                integrity.append(
                    IntegrityEvidence(path=resolved_path, expected_sha256=None)
                )

        permission_fixtures: tuple[PermissionEvidence, ...] = ()
        if self._scenario is SecurityScenario.PERMISSAO_FROUXA:
            permission_fixtures = (
                PermissionEvidence(
                    path=self._project_root / "config" / "runtime.json",
                    group_writable=True,
                    world_writable=True,
                    synthetic=True,
                ),
            )

        encoded_payload_samples: tuple[str, ...] = ()
        simulated_subprocess_commands: tuple[str, ...] = ()
        if self._scenario is SecurityScenario.OBFUSCATION:
            encoded_payload_samples = ("U1lOVEhFVElDX09OTFk=",)
            simulated_subprocess_commands = (
                "powershell.exe -EncodedCommand <synthetic-marker>",
            )
        persistence_fixtures: tuple[PersistenceEvidence, ...] = ()
        if self._scenario is SecurityScenario.PERSISTENCE:
            persistence_fixtures = (
                PersistenceEvidence(
                    mechanism="scheduled_task",
                    name="SARR_SYNTHETIC_TASK",
                ),
                PersistenceEvidence(
                    mechanism="autorun",
                    name="SARR_SYNTHETIC_AUTORUN",
                ),
            )

        ghost_port_attempts: tuple[GhostPortAttempt, ...] = ()
        if self._scenario is SecurityScenario.GHOST_PORT:
            ghost_port_attempts = (
                GhostPortAttempt(
                    host="127.0.0.1",
                    port=44444,
                    method="GET",
                    path="/synthetic-canary",
                    signature_sha256=hashlib.sha256(
                        b"GET /synthetic-canary HTTP/1.1|SARR_SYNTHETIC"
                    ).hexdigest(),
                ),
            )

        return (
            ports,
            tuple(integrity),
            self._discover_local_files(),
            permission_fixtures,
            10 if self._scenario is SecurityScenario.BRUTE_FORCE else 0,
            encoded_payload_samples,
            simulated_subprocess_commands,
            persistence_fixtures,
            self._scenario is SecurityScenario.CANARY_ACCESS,
            ghost_port_attempts,
        )

    def _discover_local_files(self) -> tuple[Path, ...]:
        discovered: set[Path] = set()
        for relative_directory in ("config", "schemas"):
            directory = (self._project_root / relative_directory).resolve()
            try:
                directory.relative_to(self._project_root)
            except ValueError as error:
                raise ValueError(
                    "Discovery directories must remain inside project root."
                ) from error
            if not directory.is_dir():
                continue
            for candidate in directory.rglob("*"):
                if candidate.name == ".gitkeep" or candidate.is_symlink():
                    continue
                if not candidate.is_file():
                    continue
                resolved = candidate.resolve()
                try:
                    resolved.relative_to(self._project_root)
                except ValueError as error:
                    raise ValueError(
                        "Discovered files must remain inside project root."
                    ) from error
                discovered.add(resolved)
        return tuple(sorted(discovered))

    def _publish_atomic_tactic(
        self,
        mitre_id: str,
        simulation: str,
        item_count: int,
        source: str,
    ) -> None:
        self._orchestrator.events.publish(
            Event(
                run_id=self._run.run_id,
                name="atomic.tactic.completed",
                payload={
                    "mitre_id": mitre_id,
                    "simulation": simulation,
                    "item_count": item_count,
                    "source": source,
                },
            )
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
            details={
                **finding.evidence,
                "vetor_ataque": finding.vetor_ataque,
                "remediacao": finding.remediacao,
                "mitre_id": finding.mitre_id,
                "acao_bloqueio": finding.acao_bloqueio,
            },
        )
        self._orchestrator.events.publish(
            Event(
                run_id=self._run.run_id,
                name="finding.created",
                payload={
                    "finding_id": str(record.finding_id),
                    "severity": record.severity,
                    "title": finding.event_name,
                    "description": finding.summary,
                    "evidence": finding.evidence,
                    "vetor_ataque": finding.vetor_ataque,
                    "remediacao": finding.remediacao,
                    "mitre_id": finding.mitre_id,
                    "acao_bloqueio": finding.acao_bloqueio,
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
    "hardening_score",
    "restore_known_baselines",
]
