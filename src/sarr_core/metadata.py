"""Read-only export of the most recently persisted execution."""

import json
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Mapping

from core.redaction import sanitize_json_value


class MetadataExportError(RuntimeError):
    """Raised when persisted run metadata cannot be safely exported."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MetadataExportError(f"Duplicate key in persisted JSON: {key}.")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise MetadataExportError(f"Non-finite value in persisted JSON: {value}.")


class MetadataManager:
    """Exports locally persisted records without creating or migrating a DB."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)

    def export_latest_run(self, output_path: str | Path) -> Path:
        if not self._database_path.is_file():
            raise MetadataExportError(
                f"Persisted database does not exist: {self._database_path}"
            )

        try:
            document = self._read_latest_run()
            return self._write_json(Path(output_path), document)
        except (OSError, sqlite3.Error, json.JSONDecodeError) as error:
            raise MetadataExportError(
                f"Could not export persisted run metadata: {error}"
            ) from error

    def _read_latest_run(self) -> dict[str, object]:
        database_uri = f"{self._database_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(database_uri, uri=True, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")

            run_row = connection.execute(
                """
                SELECT run_id, created_at_utc, mode, state,
                       engagement_id, environment
                FROM runs
                ORDER BY created_at_utc DESC, run_id DESC
                LIMIT 1
                """
            ).fetchone()
            if run_row is None:
                raise MetadataExportError(
                    "No persisted execution is available to export."
                )

            run_id = run_row["run_id"]
            return {
                "schema_version": 1,
                "run": self._safe_row(run_row),
                "events": self._read_rows(
                    connection,
                    """
                    SELECT event_id, name, timestamp_utc, payload_json
                    FROM events WHERE run_id = ?
                    ORDER BY timestamp_utc, event_id
                    """,
                    run_id,
                    json_column="payload_json",
                ),
                "metrics": self._read_rows(
                    connection,
                    """
                    SELECT metric_id, timestamp_utc, name, value, unit,
                           dimensions_json
                    FROM metrics WHERE run_id = ?
                    ORDER BY timestamp_utc, metric_id
                    """,
                    run_id,
                    json_column="dimensions_json",
                ),
                "findings": self._read_rows(
                    connection,
                    """
                    SELECT finding_id, created_at_utc, severity, title,
                           description, details_json
                    FROM findings WHERE run_id = ?
                    ORDER BY created_at_utc, finding_id
                    """,
                    run_id,
                    json_column="details_json",
                ),
                "approvals": self._read_rows(
                    connection,
                    """
                    SELECT approval_id, created_at_utc, approver, decision,
                           details_json
                    FROM approvals WHERE run_id = ?
                    ORDER BY created_at_utc, approval_id
                    """,
                    run_id,
                    json_column="details_json",
                ),
            }

    @staticmethod
    def _safe_row(row: sqlite3.Row) -> dict[str, object]:
        sanitized = sanitize_json_value(dict(row))
        if not isinstance(sanitized, dict):
            raise MetadataExportError("Persisted run row could not be sanitized.")
        return sanitized

    @classmethod
    def _read_rows(
        cls,
        connection: sqlite3.Connection,
        query: str,
        run_id: str,
        *,
        json_column: str,
    ) -> list[dict[str, object]]:
        exported: list[dict[str, object]] = []
        for row in connection.execute(query, (run_id,)):
            item = dict(row)
            raw_json = item.pop(json_column)
            if not isinstance(raw_json, str):
                raise MetadataExportError(
                    f"Persisted field {json_column} is not valid text."
                )
            parsed = json.loads(
                raw_json,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
            if not isinstance(parsed, Mapping):
                raise MetadataExportError(
                    f"Persisted field {json_column} must contain a JSON object."
                )
            item[json_column.removesuffix("_json")] = parsed
            sanitized = sanitize_json_value(item)
            if not isinstance(sanitized, dict):
                raise MetadataExportError("Persisted row could not be sanitized.")
            exported.append(sanitized)
        return exported

    @staticmethod
    def _write_json(output_path: Path, document: dict[str, object]) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                dir=output_path.parent,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(
                    document,
                    stream,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, output_path)
            temporary_path = None
            return output_path
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
