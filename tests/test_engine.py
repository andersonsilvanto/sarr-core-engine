import contextlib
import importlib.util
import io
import unittest
from unittest.mock import patch

from core import (
    InvalidStateTransitionError,
    RunContext,
    RunState,
    RunStateMachine,
)
from sarr_core.cli import build_parser, main
from sarr_core.core.engine import Engine, EngineState
from sarr_core.core.run_context import RunContext as PublicRunContext


class EngineTransitionTests(unittest.TestCase):
    def test_public_engine_states_match_run_state(self) -> None:
        self.assertEqual(
            {state.value for state in EngineState},
            {state.value for state in RunState},
        )

    def test_public_engine_follows_permitted_lifecycle(self) -> None:
        engine = Engine()
        self.assertEqual(engine.state, EngineState.IDLE)
        self.assertIsInstance(engine.context, PublicRunContext)

        for state in (
            EngineState.VALIDATING,
            EngineState.READY,
            EngineState.RUNNING,
        ):
            self.assertEqual(engine.transition_to(state), state)

        started = engine.started_at_utc
        self.assertIsNotNone(started)
        self.assertIsNone(engine.ended_at_utc)
        engine.transition_to(EngineState.STOPPING)
        engine.transition_to(EngineState.STOPPED)
        ended = engine.ended_at_utc
        self.assertIsNotNone(ended)
        assert started is not None and ended is not None
        self.assertEqual(started.utcoffset(), ended.utcoffset())
        self.assertEqual(started.utcoffset().total_seconds(), 0)

    def test_public_engine_rejects_invalid_transitions(self) -> None:
        engine = Engine()
        invalid_sequences = (
            (EngineState.RUNNING,),
            (EngineState.VALIDATING, EngineState.RUNNING),
            (EngineState.VALIDATING, EngineState.READY, EngineState.STOPPED),
        )
        for sequence in invalid_sequences:
            with self.subTest(sequence=sequence):
                engine = Engine()
                for target in sequence[:-1]:
                    engine.transition_to(target)
                state_before = engine.state
                with self.assertRaises(InvalidStateTransitionError):
                    engine.transition_to(sequence[-1])
                self.assertEqual(engine.state, state_before)

    def test_public_engine_exposes_failed_terminal_transition(self) -> None:
        engine = Engine()
        engine.transition_to(EngineState.VALIDATING)
        engine.transition_to(EngineState.FAILED)
        self.assertEqual(engine.state, EngineState.FAILED)
        self.assertIsNotNone(engine.ended_at_utc)

    def test_public_engine_transitions_to_completed_and_exposes_end_time(self) -> None:
        engine = Engine()
        for state in (
            EngineState.VALIDATING,
            EngineState.READY,
            EngineState.RUNNING,
            EngineState.COMPLETED,
        ):
            engine.transition_to(state)

        self.assertEqual(engine.state, EngineState.COMPLETED)
        self.assertIsNotNone(engine.ended_at_utc)

    def test_public_engine_can_revalidate_after_blocked_state(self) -> None:
        engine = Engine()
        engine.transition_to(EngineState.VALIDATING)
        engine.transition_to(EngineState.BLOCKED)
        self.assertEqual(engine.state, EngineState.BLOCKED)
        engine.transition_to(EngineState.VALIDATING)
        self.assertEqual(engine.state, EngineState.VALIDATING)

    def test_valid_transitions_follow_validation_and_ready_gates(self) -> None:
        machine = RunStateMachine(RunContext.create("test"))

        self.assertEqual(machine.transition_to(RunState.VALIDATING), RunState.VALIDATING)
        self.assertEqual(machine.transition_to(RunState.READY), RunState.READY)
        self.assertEqual(machine.transition_to(RunState.RUNNING), RunState.RUNNING)
        started_at_utc = machine.started_at_utc
        self.assertIsNotNone(started_at_utc)
        self.assertIsNone(machine.ended_at_utc)
        self.assertEqual(machine.transition_to(RunState.COMPLETED), RunState.COMPLETED)
        ended_at_utc = machine.ended_at_utc
        self.assertIsNotNone(ended_at_utc)
        assert started_at_utc is not None and ended_at_utc is not None
        self.assertEqual(started_at_utc.utcoffset().total_seconds(), 0)
        self.assertEqual(ended_at_utc.utcoffset().total_seconds(), 0)

    def test_illegal_transition_is_rejected_without_state_change(self) -> None:
        machine = RunStateMachine(RunContext.create("test"))

        with self.assertRaises(InvalidStateTransitionError):
            machine.transition_to(RunState.RUNNING)

        self.assertEqual(machine.state, RunState.IDLE)

    def test_status_command_does_not_start_a_run(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--status"])

        self.assertEqual(result, 0)
        self.assertIn("Estado da execução: IDLE", output.getvalue())
        self.assertIn("Kill-switch: inativo", output.getvalue())

    @unittest.skipUnless(
        importlib.util.find_spec("tkinter") is not None,
        "Tkinter is not installed",
    )
    def test_gui_command_dispatches_to_gui_entry_point(self) -> None:
        with patch("sarr_core.gui.launch_gui", return_value=0) as launch:
            self.assertEqual(main(["--gui"]), 0)
        launch.assert_called_once_with()

    def test_simulation_command_completes_local_security_audit(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["--run-sim"])

        rendered = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("Nmap limitado a 127.0.0.1", rendered)
        self.assertIn("Tshark apenas em captura offline autorizada", rendered)
        self.assertIn("scope.validated", rendered)
        self.assertIn("run.started", rendered)
        self.assertIn("security.audit.completed", rendered)
        self.assertIn("Estado final: COMPLETED", rendered)

    def test_unauthorized_port_scenario_reports_blocked_exit_status(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                ["--run-sim", "--scenario", "unauthorized-port"]
            )

        self.assertEqual(result, 2)
        self.assertIn("security.port.exposed", output.getvalue())
        self.assertIn("Estado final: BLOCKED", output.getvalue())

    def test_portuguese_security_scenarios_are_available_in_cli(self) -> None:
        parser = build_parser()
        for scenario in (
            "porta_desprotegida",
            "permissao_frouxa",
            "hash_adulterado",
        ):
            with self.subTest(scenario=scenario):
                arguments = parser.parse_args(
                    ["--run-sim", "--scenario", scenario]
                )
                self.assertEqual(arguments.scenario, scenario)


if __name__ == "__main__":
    unittest.main()
