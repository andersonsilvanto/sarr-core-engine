"""Compatibility-facing execution core for the SARR-Core Engine."""

from sarr_core.core.engine import Engine, EngineState, InvalidStateTransitionError
from sarr_core.core.run_context import RunContext

__all__ = [
    "Engine",
    "EngineState",
    "InvalidStateTransitionError",
    "RunContext",
]
