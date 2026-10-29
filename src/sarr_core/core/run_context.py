"""Public import path for the immutable identity of a run.

The state machine owns lifecycle state and UTC start/end timestamps. Validated
scope metadata remains owned by ``CoreOrchestrator`` so unvalidated data cannot
be mistaken for authorization.
"""

from core.context import RunContext

__all__ = ["RunContext"]
