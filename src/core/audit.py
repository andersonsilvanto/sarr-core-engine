"""Structured JSON Lines audit trail with restrictive payload handling."""

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from threading import RLock
from typing import Callable, Mapping
from uuid import UUID

from core.database import Database
from core.events import Event, EventBus
from core.redaction import sanitize_json_value
from core.repositories import (
    ApprovalRecord,
    ApprovalRepository,
    EventRepository,
    FindingRecord,
    FindingRepository,
    MetricRecord,
    MetricRepository,
    RunRepository,
)


_AUDIT_FIELDS: dict[str, tuple[str, ...]] = {
    "run.created": ("mode", "state"),
    "run.state_changed": ("from", "to"),
    "run.started": ("mode", "environment", "engagement_id"),
    "scope.validated": (
        "engagement_id",
        "environment",
        "mode",
        "target_count",
        "module_count",
    ),
    "metric.sample": (
        "metric",
        "value",
        "unit",
        "cpu_percent",
        "ram_percent",
        "rtt_ms",
        "drop_rate",
        "status_code",
        "duration_ms",
        "volume_bytes",
    ),
    "safety.triggered": ("reason_code",),
    "run.stopped": ("reason_code",),
    "finding.created": (
        "finding_id",
        "severity",
        "title",
        "description",
        "evidence",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "module.executed": ("module",),
    "approval.created": ("approval_id", "decision"),
    "security.audit.started": ("port_evidence_count", "integrity_check_count"),
    "security.audit.completed": ("finding_count",),
    "integrity.baseline.missing": (
        "path",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "atomic.tactic.completed": (
        "mitre_id",
        "simulation",
        "item_count",
        "source",
    ),
    "security.port.reviewed": ("host", "port", "service"),
    "security.port.exposed": (
        "host",
        "port",
        "service",
        "authentication",
        "source",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "integrity.hash.verified": ("path", "sha256"),
    "integrity.hash.mismatch": (
        "path",
        "expected_sha256",
        "actual_sha256",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "integrity.audit.failed": (
        "path",
        "error_type",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "security.permission.audit_unavailable": (
        "path",
        "platform",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "security.permission.audit_failed": (
        "path",
        "error_type",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "security.permission.excessive": (
        "path",
        "group_writable",
        "world_writable",
        "source",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "security.permission.verified": (
        "path",
        "group_writable",
        "world_writable",
        "source",
    ),
    "auth.brute_force.detected": (
        "failure_count",
        "threshold",
        "source",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "evasion.obfuscation.detected": (
        "mitre_id",
        "base64_sample_count",
        "suspicious_command_count",
        "source",
        "summary",
        "vetor_ataque",
        "remediacao",
        "acao_bloqueio",
    ),
    "persistence.point.detected": (
        "mechanism",
        "fixture_name",
        "source",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "deception.canary.triggered": (
        "path",
        "reason",
        "source",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "security.state.healed": (
        "path",
        "sha256",
        "status",
        "source",
    ),
    "deception.ghost_port.engaged": (
        "host",
        "port",
        "method",
        "path",
        "request_signature_sha256",
        "source",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "external.scanner.status": ("tool", "status"),
    "external.scanner.unavailable": (
        "tool",
        "fallback",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "external.scanner.failed": (
        "tool",
        "reason",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "network.nmap.port_discovered": (
        "host",
        "port",
        "protocol",
        "service",
        "source",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "network.tshark.capture_analyzed": (
        "capture_name",
        "frame_count",
        "analysis_signature_sha256",
        "source",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
    "network.wifi.inventory_collected": (
        "approval_reference",
        "approved_by",
        "activity",
        "source",
        "rssi_estimated",
        "access_point_count",
        "discarded_count",
        "access_points",
    ),
    "network.correlation.vulnerability_detected": (
        "host",
        "port",
        "service",
        "protocols",
        "frame_count",
        "capture_name",
        "source",
        "severity",
        "summary",
        "vetor_ataque",
        "remediacao",
        "mitre_id",
        "acao_bloqueio",
    ),
}


class AuditPersistenceError(RuntimeError):
    """Raised when an audit record cannot be committed to SQLite and JSONL."""


def _safe_payload(event: Event) -> dict[str, object]:
    fields = _AUDIT_FIELDS.get(event.name, ())
    payload: dict[str, object] = {}
    for field in fields:
        if field in event.payload:
            safe_value = sanitize_json_value(event.payload[field], key=field)
            payload[field] = safe_value
    return payload


def _safe_event_name(name: str) -> str:
    return name if name in _AUDIT_FIELDS else "event.other"


class AuditTrail:
    def __init__(
        self,
        database: Database,
        event_repository: EventRepository,
        run_repository: RunRepository,
        jsonl_path: str | Path,
    ) -> None:
        self._database = database
        self._events = event_repository
        self._runs = run_repository
        self.path = Path(jsonl_path)
        self._lock = RLock()

    def record_event(self, event: Event) -> None:
        if not isinstance(event, Event):
            raise TypeError("AuditTrail exige um Event.")
        try:
            payload = _safe_payload(event)
            event_name = _safe_event_name(event.name)
            entry = {
                "event_id": str(event.event_id),
                "event_type": event_name,
                "payload": payload,
                "run_id": str(event.run_id) if event.run_id is not None else None,
                "timestamp_utc": (
                    event.timestamp_utc.isoformat().replace("+00:00", "Z")
                ),
            }
            line = (
                json.dumps(
                    entry,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (ValueError, TypeError) as error:
            raise AuditPersistenceError(
                f"Could not serialize audit event {event.event_id}."
            ) from error

        try:
            with self._database.transaction(), self._lock:
                if event.name == "run.created" and event.run_id is not None:
                    mode = payload.get("mode")
                    state = payload.get("state")
                    if not isinstance(mode, str) or not isinstance(state, str):
                        raise ValueError("run.created requires mode and state.")
                    self._runs.create(
                        event.run_id,
                        mode,
                        state=state,
                        created_at_utc=event.timestamp_utc,
                    )
                elif event.name == "run.state_changed" and event.run_id is not None:
                    state = payload.get("to")
                    if not isinstance(state, str):
                        raise ValueError("run.state_changed requires a target state.")
                    self._runs.update_state(event.run_id, state)
                elif event.name == "scope.validated" and event.run_id is not None:
                    engagement_id = payload.get("engagement_id")
                    environment = payload.get("environment")
                    if not isinstance(engagement_id, str) or not isinstance(
                        environment, str
                    ):
                        raise ValueError(
                            "scope.validated requires engagement and environment."
                        )
                    self._runs.update_scope(
                        event.run_id,
                        engagement_id=engagement_id,
                        environment=environment,
                    )
                elif event.name == "run.started" and event.run_id is not None:
                    self._runs.update_state(event.run_id, "RUNNING")
                elif event.name == "run.stopped" and event.run_id is not None:
                    self._runs.update_state(event.run_id, "STOPPED")

                self._events.create(
                    event_id=event.event_id,
                    run_id=event.run_id,
                    name=event_name,
                    timestamp_utc=event.timestamp_utc,
                    payload=payload,
                )
                self._append(line)
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError) as error:
            raise AuditPersistenceError(
                f"Could not persist audit event {event.event_id}."
            ) from error

    def _append(self, line: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b") as output:
            output.seek(0, os.SEEK_END)
            original_size = output.tell()
            try:
                output.write(line)
                output.flush()
                os.fsync(output.fileno())
            except OSError:
                output.seek(original_size)
                output.truncate()
                output.flush()
                raise

    def export_jsonl(self, destination: str | Path) -> Path:
        target = Path(destination)
        if target.resolve() == self.path.resolve():
            raise ValueError("Export destination must differ from the active audit log.")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as output:
                temporary_path = Path(output.name)
                with self._lock, self.path.open("rb") as source:
                    while chunk := source.read(64 * 1024):
                        output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


class Persistence:
    """Persistence facade and event-bus integration for one engine instance."""

    def __init__(
        self,
        database_path: str | Path,
        audit_path: str | Path,
    ) -> None:
        self.database = Database(database_path)
        self.runs = RunRepository(self.database)
        self.events = EventRepository(self.database)
        self.metrics = MetricRepository(self.database)
        self.findings = FindingRepository(self.database)
        self.approvals = ApprovalRepository(self.database)
        self.audit = AuditTrail(
            self.database, self.events, self.runs, audit_path
        )
        self._event_bus: EventBus | None = None
        self._failure_handler: Callable[[Event, AuditPersistenceError], None] | None = None

    def attach(
        self,
        event_bus: EventBus,
        *,
        on_audit_failure: Callable[[Event, AuditPersistenceError], None] | None = None,
    ) -> None:
        if self._event_bus is not None:
            if self._event_bus is event_bus:
                return
            raise RuntimeError("Persistence is already attached to another EventBus.")
        if not isinstance(event_bus, EventBus):
            raise TypeError("event_bus must be an EventBus.")
        self._failure_handler = on_audit_failure
        event_bus.subscribe(self._record_event)
        self._event_bus = event_bus

    def _record_event(self, event: Event) -> None:
        try:
            self.audit.record_event(event)
        except AuditPersistenceError as error:
            if self._failure_handler is not None:
                self._failure_handler(event, error)
            raise

    def record_metric(
        self,
        run_id: UUID,
        name: str,
        value: float,
        *,
        unit: str,
        dimensions: Mapping[str, object] | None = None,
    ) -> MetricRecord:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._require_event_bus()
        with self.database.transaction():
            metric = self.metrics.create(
                run_id,
                name,
                value,
                unit=unit,
                dimensions=dimensions,
            )
            self._event_bus.publish(
                Event(
                    run_id=run_id,
                    name="metric.sample",
                    payload={
                        "metric": metric.name,
                        "value": metric.value,
                        "unit": metric.unit,
                        "dimensions": dict(dimensions or {}),
                    },
                )
            )
        return metric

    def create_finding(
        self,
        run_id: UUID,
        *,
        severity: str,
        title: str,
        description: str = "",
        details: Mapping[str, object] | None = None,
    ) -> FindingRecord:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._require_event_bus()
        with self.database.transaction():
            finding = self.findings.create(
                run_id,
                severity=severity,
                title=title,
                description=description,
                details=details,
            )
            self._event_bus.publish(
                Event(
                    run_id=run_id,
                    name="finding.created",
                    payload={
                        "finding_id": str(finding.finding_id),
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                        **dict(details or {}),
                    },
                )
            )
        return finding

    def create_approval(
        self,
        run_id: UUID,
        *,
        approver: str,
        decision: str,
        details: Mapping[str, object] | None = None,
    ) -> ApprovalRecord:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._require_event_bus()
        with self.database.transaction():
            approval = self.approvals.create(
                run_id,
                approver=approver,
                decision=decision,
                details=details,
            )
            self._event_bus.publish(
                Event(
                    run_id=run_id,
                    name="approval.created",
                    payload={
                        "approval_id": str(approval.approval_id),
                        "decision": approval.decision,
                    },
                )
            )
        return approval

    def export_jsonl(self, destination: str | Path) -> Path:
        return self.audit.export_jsonl(destination)

    def close(self) -> None:
        self.database.close()

    def _require_event_bus(self) -> None:
        if self._event_bus is None:
            raise RuntimeError("Persistence must be attached to an EventBus first.")
