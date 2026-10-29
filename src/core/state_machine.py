"""Máquina explícita de estados por execução."""

from enum import Enum
from datetime import datetime, timezone
from threading import RLock

from core.context import RunContext


class RunState(Enum):
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class InvalidTransitionError(ValueError):
    """Raised when a run attempts a transition not present in the state graph."""


InvalidStateTransitionError = InvalidTransitionError


_ALLOWED_TRANSITIONS = {
    RunState.IDLE: {RunState.VALIDATING},
    RunState.VALIDATING: {
        RunState.READY,
        RunState.STOPPING,
        RunState.BLOCKED,
        RunState.FAILED,
    },
    RunState.READY: {
        RunState.RUNNING,
        RunState.STOPPING,
        RunState.BLOCKED,
        RunState.FAILED,
    },
    RunState.RUNNING: {
        RunState.STOPPING,
        RunState.BLOCKED,
        RunState.FAILED,
        RunState.COMPLETED,
    },
    RunState.STOPPING: {RunState.STOPPED, RunState.FAILED},
    RunState.BLOCKED: {RunState.VALIDATING, RunState.STOPPING},
    RunState.STOPPED: set(),
    RunState.FAILED: set(),
    RunState.COMPLETED: set(),
}


class RunStateMachine:
    def __init__(self, context: RunContext) -> None:
        if not isinstance(context, RunContext):
            raise TypeError("RunStateMachine exige um RunContext válido.")
        self._context = context
        self._state = RunState.IDLE
        self._started_at_utc: datetime | None = None
        self._ended_at_utc: datetime | None = None
        self._lock = RLock()

    @property
    def context(self) -> RunContext:
        return self._context

    @property
    def state(self) -> RunState:
        with self._lock:
            return self._state

    @property
    def started_at_utc(self) -> datetime | None:
        with self._lock:
            return self._started_at_utc

    @property
    def ended_at_utc(self) -> datetime | None:
        with self._lock:
            return self._ended_at_utc

    def transition(self, target: RunState) -> RunState:
        if not isinstance(target, RunState):
            raise TypeError("target deve ser um RunState.")
        with self._lock:
            if target not in _ALLOWED_TRANSITIONS[self._state]:
                raise InvalidTransitionError(
                    f"Transição inválida: {self._state.value} -> {target.value}."
                )
            now = datetime.now(timezone.utc)
            if target is RunState.RUNNING:
                self._started_at_utc = now
            if target in (RunState.STOPPED, RunState.FAILED, RunState.COMPLETED):
                self._ended_at_utc = now
            self._state = target
            return self._state

    def transition_to(self, new_state: RunState) -> RunState:
        """Transition to a state only when the explicit state graph permits it."""
        return self.transition(new_state)
