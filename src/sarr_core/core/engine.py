"""Strict state-machine facade at the public ``sarr_core`` import path."""

from datetime import datetime
from enum import Enum

from core.context import RunContext
from core.state_machine import (
    InvalidStateTransitionError,
    RunState,
    RunStateMachine,
)


class EngineState(Enum):
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


_RUN_STATES = {state.value: state for state in RunState}


class Engine:
    """Expose the lifecycle state machine without bypassing its transition graph.

    Full scope validation and operational authorization are performed by
    ``CoreOrchestrator``; this facade provides the small state-machine API for
    callers that need lifecycle transitions only.
    """

    def __init__(self, context: RunContext | None = None) -> None:
        self._context = context or RunContext.create("simulation")
        self._machine = RunStateMachine(self._context)

    @property
    def context(self) -> RunContext:
        return self._context

    @property
    def state(self) -> EngineState:
        return EngineState(self._machine.state.value)

    @property
    def started_at_utc(self) -> datetime | None:
        return self._machine.started_at_utc

    @property
    def ended_at_utc(self) -> datetime | None:
        return self._machine.ended_at_utc

    def transition_to(self, new_state: EngineState) -> EngineState:
        if not isinstance(new_state, EngineState):
            raise TypeError("new_state must be an EngineState.")
        target = _RUN_STATES[new_state.value]
        self._machine.transition_to(target)
        return new_state


__all__ = ["Engine", "EngineState", "InvalidStateTransitionError"]
