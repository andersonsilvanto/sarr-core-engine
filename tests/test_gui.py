import tkinter as tk
import unittest
from unittest.mock import patch

from sarr_core.gui import LocalDashboard, launch_gui


class FakeRoot:
    def __init__(self) -> None:
        self.mainloop_called = False

    def mainloop(self) -> None:
        self.mainloop_called = True


class GuiTests(unittest.TestCase):
    def test_soc_event_severity_classification(self) -> None:
        self.assertEqual(
            LocalDashboard._severity_for_event("security.port.exposed"),
            "CRITICAL",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event(
                "security.permission.audit_unavailable"
            ),
            "WARNING",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event("security.audit.completed"),
            "INFO",
        )

    def test_soc_posture_fails_closed_for_findings_and_kill_switch(self) -> None:
        self.assertEqual(
            LocalDashboard._posture_for("COMPLETED", 0, False),
            ("SECURE", "Posture.SECURE.TLabel"),
        )
        self.assertEqual(
            LocalDashboard._posture_for("COMPLETED", 1, False),
            ("VULNERABLE", "Posture.VULNERABLE.TLabel"),
        )
        self.assertEqual(
            LocalDashboard._posture_for("BLOCKED", 0, True),
            ("ATTACK / KILL-SWITCH", "Posture.ATTACK.TLabel"),
        )

    def test_launch_gui_creates_dashboard_and_runs_event_loop(self) -> None:
        root = FakeRoot()
        with patch("sarr_core.gui.LocalDashboard") as dashboard:
            result = launch_gui(root_factory=lambda: root)  # type: ignore[arg-type]

        self.assertEqual(result, 0)
        self.assertTrue(root.mainloop_called)
        dashboard.assert_called_once_with(root)

    def test_launch_gui_reports_missing_desktop_display(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "desktop display"):
            launch_gui(
                root_factory=lambda: (_ for _ in ()).throw(
                    tk.TclError("no display")
                )
            )


if __name__ == "__main__":
    unittest.main()
