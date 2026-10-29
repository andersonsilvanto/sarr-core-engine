"""Enforcement de limites operacionais por execução."""

from collections import deque
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable
from uuid import UUID

from core.kill_switch import KillSwitch
from core.scope_validator import ScopeLimits


class OperationalLimitExceeded(RuntimeError):
    """Raised after a per-scope operational threshold trips the kill-switch."""


class OperationLease(AbstractContextManager["OperationLease"]):
    def __init__(self, limits: "OperationalLimitEnforcer") -> None:
        self._limits = limits
        self._closed = False

    def __enter__(self) -> "OperationLease":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        self.close()
        return False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._limits.end_operation()


class OperationalLimitEnforcer:
    RTT_LIMIT_MS = 1500
    SERVER_ERROR_RATE_LIMIT = 0.05
    SERVER_ERROR_MINIMUM_SAMPLE = 10

    def __init__(
        self,
        run_id: UUID,
        limits: ScopeLimits,
        kill_switch: KillSwitch,
        *,
        clock: Callable[[], datetime] | None = None,
        scope_valid_from_utc: datetime | None = None,
        scope_valid_until_utc: datetime | None = None,
    ) -> None:
        if (scope_valid_from_utc is None) != (scope_valid_until_utc is None):
            raise ValueError("Both scope validity timestamps must be provided together.")
        for timestamp in (scope_valid_from_utc, scope_valid_until_utc):
            if timestamp is not None and (
                timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0)
            ):
                raise ValueError("Scope validity timestamps must be in UTC.")
        if (
            scope_valid_from_utc is not None
            and scope_valid_until_utc is not None
            and scope_valid_until_utc <= scope_valid_from_utc
        ):
            raise ValueError("Scope validity end must follow its start.")
        self._run_id = run_id
        self._limits = limits
        self._kill_switch = kill_switch
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._scope_valid_from_utc = scope_valid_from_utc
        self._scope_valid_until_utc = scope_valid_until_utc
        self._lock = RLock()
        self._started_at: datetime | None = None
        self._active_operations = 0
        self._operation_starts: deque[datetime] = deque()
        self._responses: deque[tuple[datetime, bool]] = deque()
        self._volume_bytes = 0

    @property
    def active_operations(self) -> int:
        with self._lock:
            return self._active_operations

    @property
    def volume_bytes(self) -> int:
        with self._lock:
            return self._volume_bytes

    def start(self) -> None:
        with self._lock:
            self._kill_switch.assert_clear()
            if self._started_at is not None:
                raise RuntimeError("Limites operacionais já iniciados.")
            now = self._now()
            self._check_scope_window_locked(now)
            self._started_at = now

    def check_duration(self) -> None:
        with self._lock:
            self._check_duration_locked(self._now())

    def begin_operation(self) -> OperationLease:
        with self._lock:
            self._kill_switch.assert_clear()
            now = self._now()
            self._check_duration_locked(now)
            self._discard_before(self._operation_starts, now)
            window = self._limits.measurement_window_seconds
            next_count = len(self._operation_starts) + 1
            if next_count > self._limits.max_rate_per_second * window:
                self._trip(
                    f"taxa operacional excedida na janela de {window}s",
                    reason_code="rate_limit",
                )
            if self._active_operations >= self._limits.max_concurrency:
                self._trip(
                    "limite de concorrência excedido",
                    reason_code="concurrency_limit",
                )
            self._operation_starts.append(now)
            self._active_operations += 1
        return OperationLease(self)

    def end_operation(self) -> None:
        with self._lock:
            if self._active_operations <= 0:
                raise RuntimeError("Não há operação ativa para encerrar.")
            try:
                if not self._kill_switch.is_triggered:
                    self._check_duration_locked(self._now())
            finally:
                self._active_operations -= 1

    def record_result(
        self,
        *,
        rtt_ms: float,
        status_code: int,
        volume_bytes: int,
    ) -> None:
        if isinstance(rtt_ms, bool) or not isinstance(rtt_ms, (int, float)) or rtt_ms < 0:
            raise ValueError("rtt_ms deve ser um número não negativo.")
        if isinstance(status_code, bool) or not isinstance(status_code, int):
            raise ValueError("status_code deve ser um inteiro HTTP.")
        if not 100 <= status_code <= 599:
            raise ValueError("status_code deve estar entre 100 e 599.")
        if isinstance(volume_bytes, bool) or not isinstance(volume_bytes, int) or volume_bytes < 0:
            raise ValueError("volume_bytes deve ser um inteiro não negativo.")

        with self._lock:
            self._kill_switch.assert_clear()
            now = self._now()
            self._check_duration_locked(now)
            if self._active_operations <= 0:
                raise RuntimeError("record_result exige uma operação ativa.")
            if rtt_ms > self.RTT_LIMIT_MS:
                self._trip(
                    f"RTT excedeu {self.RTT_LIMIT_MS}ms",
                    reason_code="rtt_limit",
                )

            next_volume = self._volume_bytes + volume_bytes
            if next_volume > self._limits.max_volume_bytes:
                self._trip(
                    "limite de volume em bytes excedido",
                    reason_code="volume_limit",
                )
            self._volume_bytes = next_volume

            self._discard_before(self._responses, now)
            self._responses.append((now, 500 <= status_code <= 599))
            if len(self._responses) >= self.SERVER_ERROR_MINIMUM_SAMPLE:
                errors = sum(is_server_error for _, is_server_error in self._responses)
                if errors / len(self._responses) > self.SERVER_ERROR_RATE_LIMIT:
                    self._trip(
                        "taxa de respostas HTTP 5xx excedeu 5%",
                        reason_code="http_5xx_limit",
                    )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("clock deve retornar um datetime timezone-aware em UTC.")
        return now.astimezone(timezone.utc)

    def _check_duration_locked(self, now: datetime) -> None:
        self._kill_switch.assert_clear()
        if self._started_at is None:
            raise RuntimeError("Execução ainda não iniciada.")
        self._check_scope_window_locked(now)
        elapsed = (now - self._started_at).total_seconds()
        if elapsed > self._limits.max_duration_seconds:
            self._trip(
                "limite de duração excedido",
                reason_code="duration_limit",
            )

    def _check_scope_window_locked(self, now: datetime) -> None:
        valid_from = self._scope_valid_from_utc
        valid_until = self._scope_valid_until_utc
        if valid_from is not None and now < valid_from:
            self._trip(
                "Execução iniciada antes do início da validade do escopo",
                reason_code="scope_not_yet_valid",
            )
        if valid_until is not None and now > valid_until:
            self._trip(
                "Janela de validade do escopo expirou",
                reason_code="scope_expired",
            )

    def _discard_before(
        self, items: deque[datetime] | deque[tuple[datetime, bool]], now: datetime
    ) -> None:
        cutoff = now - timedelta(seconds=self._limits.measurement_window_seconds)
        while items:
            first = items[0]
            timestamp = first[0] if isinstance(first, tuple) else first
            if timestamp >= cutoff:
                break
            items.popleft()

    def _trip(self, reason: str, *, reason_code: str) -> None:
        self._kill_switch.trigger(
            reason,
            reason_code=reason_code,
            run_id=self._run_id,
        )
        raise OperationalLimitExceeded(reason)
