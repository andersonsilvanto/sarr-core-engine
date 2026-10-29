"""Kill-switch central, local e latched para interromper execuções."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from threading import RLock
from typing import Callable
from uuid import UUID


class KillSwitchTriggered(RuntimeError):
    """Raised when work is attempted while the central kill-switch is active."""


@dataclass(frozen=True)
class KillSwitchEvent:
    reason: str
    reason_code: str
    triggered_at_utc: datetime
    run_id: UUID | None = None
    blocked_run_id: UUID | None = None


KillSwitchHandler = Callable[[KillSwitchEvent], None]


class KillSwitch:
    def __init__(self) -> None:
        self._lock = RLock()
        self._event: KillSwitchEvent | None = None
        self._handlers: list[KillSwitchHandler] = []

    @property
    def is_triggered(self) -> bool:
        with self._lock:
            return self._event is not None

    @property
    def event(self) -> KillSwitchEvent | None:
        with self._lock:
            return self._event

    def subscribe(self, handler: KillSwitchHandler) -> None:
        if not callable(handler):
            raise TypeError("handler deve ser chamável.")
        with self._lock:
            if any(existing is handler for existing in self._handlers):
                raise ValueError("Esta inscrição do kill-switch já existe.")
            if self._event is not None:
                event = self._event
            else:
                self._handlers.append(handler)
                return
        handler(event)

    def trigger(
        self,
        reason: str,
        *,
        reason_code: str = "manual",
        run_id: UUID | None = None,
        blocked_run_id: UUID | None = None,
    ) -> bool:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason deve ser uma string não vazia.")
        if not isinstance(reason_code, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", reason_code
        ):
            raise ValueError("reason_code deve ser um identificador seguro.")
        if run_id is not None and not isinstance(run_id, UUID):
            raise TypeError("run_id deve ser um UUID ou None.")
        if blocked_run_id is not None and not isinstance(blocked_run_id, UUID):
            raise TypeError("blocked_run_id deve ser um UUID ou None.")
        with self._lock:
            if self._event is not None:
                return False
            event = KillSwitchEvent(
                reason=reason.strip(),
                reason_code=reason_code,
                triggered_at_utc=datetime.now(timezone.utc),
                run_id=run_id,
                blocked_run_id=blocked_run_id,
            )
            self._event = event
            handlers = tuple(self._handlers)
        for handler in handlers:
            handler(event)
        return True

    def assert_clear(self) -> None:
        event = self.event
        if event is not None:
            raise KillSwitchTriggered(
                f"Kill-switch ativo: {event.reason}"
            )
