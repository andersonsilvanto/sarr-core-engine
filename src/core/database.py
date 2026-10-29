"""SQLite persistence with versioned migrations and nested transactions."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock, local
from typing import Iterator


_MIGRATIONS = {
    1: (
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            created_at_utc TEXT NOT NULL,
            mode TEXT NOT NULL CHECK(length(mode) > 0),
            state TEXT NOT NULL,
            engagement_id TEXT,
            environment TEXT
        )
        """,
        """
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            run_id TEXT REFERENCES runs(run_id),
            name TEXT NOT NULL CHECK(length(name) > 0),
            timestamp_utc TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX events_run_timestamp_idx ON events(run_id, timestamp_utc)",
        """
        CREATE TABLE metrics (
            metric_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            timestamp_utc TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) > 0),
            value REAL NOT NULL,
            unit TEXT NOT NULL,
            dimensions_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX metrics_run_timestamp_idx ON metrics(run_id, timestamp_utc)",
        """
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            created_at_utc TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(length(severity) > 0),
            title TEXT NOT NULL CHECK(length(title) > 0),
            description TEXT NOT NULL,
            details_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX findings_run_created_idx ON findings(run_id, created_at_utc)",
        """
        CREATE TABLE approvals (
            approval_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            created_at_utc TEXT NOT NULL,
            approver TEXT NOT NULL CHECK(length(approver) > 0),
            decision TEXT NOT NULL CHECK(length(decision) > 0),
            details_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX approvals_run_created_idx ON approvals(run_id, created_at_utc)",
    ),
}


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._transaction_state = local()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 10000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self.migrate()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            depth = getattr(self._transaction_state, "depth", 0)
            savepoint = f"nested_{depth}"
            if depth == 0:
                self._connection.execute("BEGIN IMMEDIATE")
            else:
                self._connection.execute(f"SAVEPOINT {savepoint}")
            self._transaction_state.depth = depth + 1
            try:
                yield self._connection
            except BaseException:
                if depth == 0:
                    self._connection.execute("ROLLBACK")
                else:
                    self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                try:
                    if depth == 0:
                        self._connection.execute("COMMIT")
                    else:
                        self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                except sqlite3.Error:
                    if depth == 0 and self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    elif depth > 0 and self._connection.in_transaction:
                        self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                        self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                    raise
            finally:
                self._transaction_state.depth = depth

    def migrate(self) -> None:
        with self.transaction() as connection:
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            latest_version = max(_MIGRATIONS, default=0)
            if current_version > latest_version:
                raise RuntimeError(
                    f"Database version {current_version} is newer than supported "
                    f"version {latest_version}."
                )
            for version in range(current_version + 1, latest_version + 1):
                for statement in _MIGRATIONS[version]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {version}")

    def integrity_check(self) -> tuple[str, ...]:
        with self._lock:
            rows = self._connection.execute("PRAGMA integrity_check").fetchall()
        return tuple(str(row[0]) for row in rows)

    def close(self) -> None:
        with self._lock:
            self._connection.close()
