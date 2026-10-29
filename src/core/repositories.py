"""Typed SQLite repositories for SARR-Core execution data."""

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from uuid import UUID, uuid4

from core.database import Database
from core.redaction import sanitize_json_value, sanitize_text


def _utc_text(value: datetime | None = None) -> str:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Repository timestamps must be timezone-aware.")
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_text(value: Mapping[str, object]) -> str:
    sanitized = sanitize_json_value(value)
    return json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


@dataclass(frozen=True)
class RunRecord:
    run_id: UUID
    created_at_utc: str
    mode: str
    state: str
    engagement_id: str | None
    environment: str | None


@dataclass(frozen=True)
class EventRecord:
    event_id: UUID
    run_id: UUID | None
    name: str
    timestamp_utc: str
    payload: Mapping[str, object]


@dataclass(frozen=True)
class MetricRecord:
    metric_id: UUID
    run_id: UUID
    timestamp_utc: str
    name: str
    value: float
    unit: str
    dimensions: Mapping[str, object]


@dataclass(frozen=True)
class FindingRecord:
    finding_id: UUID
    run_id: UUID
    created_at_utc: str
    severity: str
    title: str
    description: str
    details: Mapping[str, object]


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: UUID
    run_id: UUID
    created_at_utc: str
    approver: str
    decision: str
    details: Mapping[str, object]


class RunRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        run_id: UUID,
        mode: str,
        *,
        state: str = "IDLE",
        created_at_utc: datetime | None = None,
    ) -> RunRecord:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        if not mode.strip() or not state.strip():
            raise ValueError("Run mode and state must be non-empty.")
        with self._database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO runs(run_id, created_at_utc, mode, state)
                VALUES (?, ?, ?, ?)
                """,
                (str(run_id), _utc_text(created_at_utc), sanitize_text(mode), state),
            )
        record = self.get(run_id)
        if record is None:
            raise RuntimeError("Run insert was not visible after commit.")
        return record

    def update_state(self, run_id: UUID, state: str) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE runs SET state = ? WHERE run_id = ?",
                (state, str(run_id)),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown run_id: {run_id}.")

    def update_scope(
        self, run_id: UUID, *, engagement_id: str, environment: str
    ) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE runs
                SET engagement_id = ?, environment = ?
                WHERE run_id = ?
                """,
                (
                    sanitize_text(engagement_id),
                    sanitize_text(environment),
                    str(run_id),
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown run_id: {run_id}.")

    def get(self, run_id: UUID) -> RunRecord | None:
        with self._database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        if row is None:
            return None
        return RunRecord(
            run_id=UUID(row["run_id"]),
            created_at_utc=row["created_at_utc"],
            mode=row["mode"],
            state=row["state"],
            engagement_id=row["engagement_id"],
            environment=row["environment"],
        )


class EventRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        *,
        event_id: UUID,
        run_id: UUID | None,
        name: str,
        timestamp_utc: datetime,
        payload: Mapping[str, object],
    ) -> EventRecord:
        payload_json = _json_text(payload)
        with self._database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO events(event_id, run_id, name, timestamp_utc, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(event_id),
                    str(run_id) if run_id is not None else None,
                    sanitize_text(name),
                    _utc_text(timestamp_utc),
                    payload_json,
                ),
            )
        return EventRecord(
            event_id=event_id,
            run_id=run_id,
            name=name,
            timestamp_utc=_utc_text(timestamp_utc),
            payload=json.loads(payload_json),
        )

    def list_for_run(self, run_id: UUID) -> tuple[EventRecord, ...]:
        with self._database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT event_id, run_id, name, timestamp_utc, payload_json
                FROM events WHERE run_id = ? ORDER BY timestamp_utc, event_id
                """,
                (str(run_id),),
            ).fetchall()
        return tuple(
            EventRecord(
                event_id=UUID(row["event_id"]),
                run_id=UUID(row["run_id"]) if row["run_id"] else None,
                name=row["name"],
                timestamp_utc=row["timestamp_utc"],
                payload=json.loads(row["payload_json"]),
            )
            for row in rows
        )

    def list_critical(self) -> tuple[EventRecord, ...]:
        critical_names = (
            "run.started",
            "scope.validated",
            "metric.sample",
            "safety.triggered",
            "run.stopped",
            "finding.created",
            "security.port.exposed",
            "integrity.hash.mismatch",
            "integrity.audit.failed",
            "security.permission.audit_failed",
            "security.permission.excessive",
            "auth.brute_force.detected",
        )
        placeholders = ",".join("?" for _ in critical_names)
        with self._database.transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT event_id, run_id, name, timestamp_utc, payload_json
                FROM events WHERE name IN ({placeholders})
                ORDER BY timestamp_utc, event_id
                """,
                critical_names,
            ).fetchall()
        return tuple(
            EventRecord(
                event_id=UUID(row["event_id"]),
                run_id=UUID(row["run_id"]) if row["run_id"] else None,
                name=row["name"],
                timestamp_utc=row["timestamp_utc"],
                payload=json.loads(row["payload_json"]),
            )
            for row in rows
        )


class MetricRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        run_id: UUID,
        name: str,
        value: float,
        *,
        unit: str,
        dimensions: Mapping[str, object] | None = None,
        timestamp_utc: datetime | None = None,
    ) -> MetricRecord:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError("Metric value must be numeric.")
        if not math.isfinite(value):
            raise ValueError("Metric value must be finite.")
        if not name.strip() or not unit.strip():
            raise ValueError("Metric name and unit must be non-empty.")
        metric_id = uuid4()
        timestamp = _utc_text(timestamp_utc)
        dimensions_json = _json_text(dimensions or {})
        with self._database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO metrics(
                    metric_id, run_id, timestamp_utc, name, value, unit, dimensions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(metric_id),
                    str(run_id),
                    timestamp,
                    sanitize_text(name),
                    float(value),
                    sanitize_text(unit),
                    dimensions_json,
                ),
            )
        return MetricRecord(
            metric_id=metric_id,
            run_id=run_id,
            timestamp_utc=timestamp,
            name=sanitize_text(name),
            value=float(value),
            unit=sanitize_text(unit),
            dimensions=json.loads(dimensions_json),
        )

    def list_for_run(self, run_id: UUID) -> tuple[MetricRecord, ...]:
        with self._database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT metric_id, run_id, timestamp_utc, name, value, unit,
                       dimensions_json
                FROM metrics WHERE run_id = ? ORDER BY timestamp_utc, metric_id
                """,
                (str(run_id),),
            ).fetchall()
        return tuple(
            MetricRecord(
                metric_id=UUID(row["metric_id"]),
                run_id=UUID(row["run_id"]),
                timestamp_utc=row["timestamp_utc"],
                name=row["name"],
                value=row["value"],
                unit=row["unit"],
                dimensions=json.loads(row["dimensions_json"]),
            )
            for row in rows
        )


class FindingRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        run_id: UUID,
        *,
        severity: str,
        title: str,
        description: str = "",
        details: Mapping[str, object] | None = None,
        finding_id: UUID | None = None,
        created_at_utc: datetime | None = None,
    ) -> FindingRecord:
        if not severity.strip() or not title.strip():
            raise ValueError("Finding severity and title must be non-empty.")
        identifier = finding_id or uuid4()
        timestamp = _utc_text(created_at_utc)
        safe_details = _json_text(details or {})
        safe_title = sanitize_text(title)
        safe_description = sanitize_text(description)
        with self._database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO findings(
                    finding_id, run_id, created_at_utc, severity, title,
                    description, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(identifier),
                    str(run_id),
                    timestamp,
                    sanitize_text(severity),
                    safe_title,
                    safe_description,
                    safe_details,
                ),
            )
        return FindingRecord(
            finding_id=identifier,
            run_id=run_id,
            created_at_utc=timestamp,
            severity=sanitize_text(severity),
            title=safe_title,
            description=safe_description,
            details=json.loads(safe_details),
        )

    def list_for_run(self, run_id: UUID) -> tuple[FindingRecord, ...]:
        with self._database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT finding_id, run_id, created_at_utc, severity, title,
                       description, details_json
                FROM findings WHERE run_id = ? ORDER BY created_at_utc, finding_id
                """,
                (str(run_id),),
            ).fetchall()
        return tuple(
            FindingRecord(
                finding_id=UUID(row["finding_id"]),
                run_id=UUID(row["run_id"]),
                created_at_utc=row["created_at_utc"],
                severity=row["severity"],
                title=row["title"],
                description=row["description"],
                details=json.loads(row["details_json"]),
            )
            for row in rows
        )


class ApprovalRepository:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(
        self,
        run_id: UUID,
        *,
        approver: str,
        decision: str,
        details: Mapping[str, object] | None = None,
        approval_id: UUID | None = None,
        created_at_utc: datetime | None = None,
    ) -> ApprovalRecord:
        if not approver.strip() or not decision.strip():
            raise ValueError("Approval approver and decision must be non-empty.")
        identifier = approval_id or uuid4()
        timestamp = _utc_text(created_at_utc)
        safe_details = _json_text(details or {})
        safe_approver = sanitize_text(approver)
        safe_decision = sanitize_text(decision)
        with self._database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO approvals(
                    approval_id, run_id, created_at_utc, approver, decision, details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(identifier),
                    str(run_id),
                    timestamp,
                    safe_approver,
                    safe_decision,
                    safe_details,
                ),
            )
        return ApprovalRecord(
            approval_id=identifier,
            run_id=run_id,
            created_at_utc=timestamp,
            approver=safe_approver,
            decision=safe_decision,
            details=json.loads(safe_details),
        )

    def list_for_run(self, run_id: UUID) -> tuple[ApprovalRecord, ...]:
        with self._database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT approval_id, run_id, created_at_utc, approver, decision,
                       details_json
                FROM approvals WHERE run_id = ? ORDER BY created_at_utc, approval_id
                """,
                (str(run_id),),
            ).fetchall()
        return tuple(
            ApprovalRecord(
                approval_id=UUID(row["approval_id"]),
                run_id=UUID(row["run_id"]),
                created_at_utc=row["created_at_utc"],
                approver=row["approver"],
                decision=row["decision"],
                details=json.loads(row["details_json"]),
            )
            for row in rows
        )
