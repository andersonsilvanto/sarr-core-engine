"""Read-only, evidence-driven local security checks and audit events."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from core.events import Event, EventBus
from core.kill_switch import KillSwitch


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class PortEvidence:
    host: str
    port: int
    service: str
    authorized: bool

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Port evidence is restricted to 127.0.0.1.")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("Port must be an integer.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("Service must be a non-empty label.")
        if not isinstance(self.authorized, bool):
            raise TypeError("authorized must be a boolean.")


@dataclass(frozen=True)
class IntegrityEvidence:
    path: Path
    expected_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("Integrity evidence path must be a pathlib.Path.")
        if not isinstance(self.expected_sha256, str) or not _SHA256.fullmatch(
            self.expected_sha256
        ):
            raise ValueError("Integrity evidence requires lowercase SHA-256.")


@dataclass(frozen=True)
class SecurityFinding:
    event_name: str
    severity: str
    summary: str
    evidence: dict[str, object]


class SecurityAudit:
    """Consumes explicitly supplied local evidence; never probes networks."""

    AUTH_FAILURE_THRESHOLD = 10

    def __init__(
        self,
        *,
        run_id: UUID,
        event_bus: EventBus,
        kill_switch: KillSwitch,
        project_root: Path,
    ) -> None:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._run_id = run_id
        self._event_bus = event_bus
        self._kill_switch = kill_switch
        self._project_root = project_root.resolve()

    def run(
        self,
        *,
        ports: tuple[PortEvidence, ...],
        integrity: tuple[IntegrityEvidence, ...],
        permission_paths: tuple[Path, ...],
        simulated_auth_failures: int = 0,
    ) -> tuple[SecurityFinding, ...]:
        findings: list[SecurityFinding] = []
        self._publish(
            "security.audit.started",
            {"port_evidence_count": len(ports), "integrity_check_count": len(integrity)},
        )

        for evidence in ports:
            if not isinstance(evidence, PortEvidence):
                raise TypeError("ports must contain PortEvidence records.")
            if evidence.authorized:
                self._publish(
                    "security.port.reviewed",
                    {
                        "host": evidence.host,
                        "port": evidence.port,
                        "service": evidence.service,
                    },
                )
                continue
            finding = SecurityFinding(
                event_name="security.port.exposed",
                severity="critical",
                summary="Unauthorized loopback service in supplied inventory.",
                evidence={
                    "host": evidence.host,
                    "port": evidence.port,
                    "service": evidence.service,
                },
            )
            findings.append(finding)
            self._publish(finding.event_name, finding.evidence)
            self._trip("unauthorized_local_service", finding.summary)

        for evidence in integrity:
            if not isinstance(evidence, IntegrityEvidence):
                raise TypeError("integrity must contain IntegrityEvidence records.")
            relative_path = self._project_relative_path(evidence.path)
            try:
                actual_sha256 = hashlib.sha256(
                    evidence.path.resolve().read_bytes()
                ).hexdigest()
            except OSError as error:
                finding = SecurityFinding(
                    event_name="integrity.audit.failed",
                    severity="critical",
                    summary="Project file could not be read for integrity verification.",
                    evidence={
                        "path": relative_path,
                        "error_type": type(error).__name__,
                    },
                )
                findings.append(finding)
                self._publish(finding.event_name, finding.evidence)
                self._trip("integrity_audit_failed", finding.summary)
                continue
            if actual_sha256 == evidence.expected_sha256:
                self._publish(
                    "integrity.hash.verified",
                    {
                        "path": relative_path,
                        "sha256": actual_sha256,
                    },
                )
                continue
            finding = SecurityFinding(
                event_name="integrity.hash.mismatch",
                severity="critical",
                summary="Project file hash differs from the supplied baseline.",
                evidence={
                    "path": relative_path,
                    "expected_sha256": evidence.expected_sha256,
                    "actual_sha256": actual_sha256,
                },
            )
            findings.append(finding)
            self._publish(finding.event_name, finding.evidence)
            self._trip("integrity_hash_mismatch", finding.summary)

        for path in permission_paths:
            relative_path = self._project_relative_path(path)
            if os.name == "nt":
                finding = SecurityFinding(
                    event_name="security.permission.audit_unavailable",
                    severity="warning",
                    summary="Windows ACL permissions could not be verified by POSIX mode bits.",
                    evidence={"path": relative_path, "platform": "windows"},
                )
                findings.append(finding)
                self._publish(finding.event_name, finding.evidence)
                continue
            try:
                mode = path.resolve().stat().st_mode
            except OSError as error:
                self._publish(
                    "security.permission.audit_failed",
                    {"path": relative_path, "error_type": type(error).__name__},
                )
                self._trip(
                    "permission_audit_failed",
                    f"Could not inspect permissions for {relative_path}.",
                )
                continue
            excessive = bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
            payload = {
                "path": relative_path,
                "group_writable": bool(mode & stat.S_IWGRP),
                "world_writable": bool(mode & stat.S_IWOTH),
            }
            if excessive:
                finding = SecurityFinding(
                    event_name="security.permission.excessive",
                    severity="critical",
                    summary="Project file is writable by group or other users.",
                    evidence=payload,
                )
                findings.append(finding)
                self._publish(finding.event_name, finding.evidence)
                self._trip("excessive_file_permissions", finding.summary)
            else:
                self._publish("security.permission.verified", payload)

        if (
            isinstance(simulated_auth_failures, bool)
            or not isinstance(simulated_auth_failures, int)
            or simulated_auth_failures < 0
        ):
            raise ValueError("simulated_auth_failures must be a non-negative integer.")
        if simulated_auth_failures >= self.AUTH_FAILURE_THRESHOLD:
            finding = SecurityFinding(
                event_name="auth.brute_force.detected",
                severity="high",
                summary="Simulated authentication-failure sequence exceeded threshold.",
                evidence={
                    "failure_count": simulated_auth_failures,
                    "threshold": self.AUTH_FAILURE_THRESHOLD,
                    "source": "synthetic_local_scenario",
                },
            )
            findings.append(finding)
            self._publish(finding.event_name, finding.evidence)
            self._trip("simulated_auth_anomaly", finding.summary)

        self._publish(
            "security.audit.completed",
            {"finding_count": len(findings)},
        )
        return tuple(findings)

    def _project_relative_path(self, path: Path) -> str:
        if not isinstance(path, Path):
            raise TypeError("Audited paths must be pathlib.Path instances.")
        resolved = path.resolve()
        try:
            return resolved.relative_to(self._project_root).as_posix()
        except ValueError as error:
            raise ValueError("Audit path must remain inside the project root.") from error

    def _publish(self, name: str, payload: dict[str, object]) -> None:
        self._event_bus.publish(Event(run_id=self._run_id, name=name, payload=payload))

    def _trip(self, reason_code: str, reason: str) -> None:
        self._kill_switch.trigger(
            reason,
            reason_code=reason_code,
            run_id=self._run_id,
            blocked_run_id=self._run_id,
        )


__all__ = [
    "IntegrityEvidence",
    "PortEvidence",
    "SecurityAudit",
    "SecurityFinding",
]
