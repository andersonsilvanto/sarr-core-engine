import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from core import (
    CoreOrchestrator,
    DuplicateRunError,
    Event,
    EventBus,
    InvalidTransitionError,
    ModuleRegistry,
    RunContext,
    RunState,
    RunStateMachine,
    ScopeValidationError,
)
from core.events import DuplicateEventError


def context() -> RunContext:
    return RunContext.create("test")


_PATH_TO_STATE = {
    RunState.IDLE: (),
    RunState.VALIDATING: (RunState.VALIDATING,),
    RunState.READY: (RunState.VALIDATING, RunState.READY),
    RunState.RUNNING: (
        RunState.VALIDATING,
        RunState.READY,
        RunState.RUNNING,
    ),
    RunState.STOPPING: (
        RunState.VALIDATING,
        RunState.READY,
        RunState.STOPPING,
    ),
    RunState.STOPPED: (
        RunState.VALIDATING,
        RunState.READY,
        RunState.STOPPING,
        RunState.STOPPED,
    ),
    RunState.BLOCKED: (RunState.VALIDATING, RunState.BLOCKED),
    RunState.FAILED: (RunState.VALIDATING, RunState.FAILED),
    RunState.COMPLETED: (
        RunState.VALIDATING,
        RunState.READY,
        RunState.RUNNING,
        RunState.COMPLETED,
    ),
}

_ALLOWED = {
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


class RunContextTests(unittest.TestCase):
    def test_create_generates_unique_id_utc_timestamp_and_mode(self) -> None:
        first = RunContext.create(" batch ")
        second = RunContext.create("batch")

        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first.mode, "batch")
        self.assertEqual(first.timestamp_utc.utcoffset(), timedelta(0))

    def test_rejects_missing_mode_and_non_utc_timestamp(self) -> None:
        run_id = uuid4()
        with self.assertRaises(ValueError):
            RunContext(run_id, datetime.now(timezone.utc), " ")
        with self.assertRaises(ValueError):
            RunContext(run_id, datetime.now(), "batch")
        with self.assertRaises(ValueError):
            RunContext(
                run_id,
                datetime.now(timezone(timedelta(hours=3))),
                "batch",
            )


class RunStateMachineTests(unittest.TestCase):
    def test_every_permitted_transition(self) -> None:
        for source, targets in _ALLOWED.items():
            for target in targets:
                with self.subTest(source=source, target=target):
                    machine = RunStateMachine(context())
                    for step in _PATH_TO_STATE[source]:
                        machine.transition(step)
                    self.assertEqual(machine.state, source)
                    self.assertEqual(machine.transition(target), target)

    def test_every_unlisted_transition_is_rejected_without_state_change(self) -> None:
        for source, targets in _ALLOWED.items():
            for target in RunState:
                if target in targets:
                    continue
                with self.subTest(source=source, target=target):
                    machine = RunStateMachine(context())
                    for step in _PATH_TO_STATE[source]:
                        machine.transition(step)
                    with self.assertRaises(InvalidTransitionError):
                        machine.transition(target)
                    self.assertEqual(machine.state, source)

    def test_requires_context_and_state_enum(self) -> None:
        with self.assertRaises(TypeError):
            RunStateMachine(None)  # type: ignore[arg-type]
        machine = RunStateMachine(context())
        with self.assertRaises(TypeError):
            machine.transition("RUNNING")  # type: ignore[arg-type]


class OrchestratorTests(unittest.TestCase):
    def test_runs_are_isolated_and_duplicate_ids_rejected(self) -> None:
        orchestrator = CoreOrchestrator()
        first = orchestrator.create_run("batch")
        second = orchestrator.create_run("interactive")
        self.assertNotEqual(first.run_id, second.run_id)

        orchestrator.transition(first.run_id, RunState.VALIDATING)

        self.assertEqual(orchestrator.get_state(first.run_id), RunState.VALIDATING)
        self.assertEqual(orchestrator.get_state(second.run_id), RunState.IDLE)
        with self.assertRaises(DuplicateRunError):
            orchestrator.register_run(first)

    def test_invalid_run_transition_does_not_change_state(self) -> None:
        orchestrator = CoreOrchestrator()
        run = orchestrator.create_run("batch")

        with self.assertRaises(ScopeValidationError):
            orchestrator.transition(run.run_id, RunState.RUNNING)
        self.assertEqual(orchestrator.get_state(run.run_id), RunState.BLOCKED)
        self.assertTrue(orchestrator.kill_switch.is_triggered)


class EventBusTests(unittest.TestCase):
    def test_dispatches_locally_and_rejects_duplicate_event_ids(self) -> None:
        bus = EventBus()
        received: list[Event] = []
        bus.subscribe(received.append, event_name="run.started")
        event = Event(run_id=uuid4(), name="run.started")

        bus.publish(event)

        self.assertEqual(received, [event])
        self.assertEqual(bus.history, (event,))
        with self.assertRaises(DuplicateEventError):
            bus.publish(event)
        self.assertEqual(received, [event])

    def test_rejects_duplicate_subscription_and_unsubscribes(self) -> None:
        bus = EventBus()
        handler = lambda event: None
        bus.subscribe(handler)
        with self.assertRaises(ValueError):
            bus.subscribe(handler)

        bus.unsubscribe(handler)
        bus.subscribe(handler)


class ModuleRegistryTests(unittest.TestCase):
    def test_registers_and_rejects_duplicate_module_name(self) -> None:
        registry = ModuleRegistry()
        module = object()

        registry.register("example", module)

        self.assertIs(registry.get("example"), module)
        self.assertEqual(registry.names(), ("example",))
        with self.assertRaises(ValueError):
            registry.register(" example ", object())
        self.assertIs(registry.unregister("example"), module)


if __name__ == "__main__":
    unittest.main()
