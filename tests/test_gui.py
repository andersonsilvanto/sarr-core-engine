import tkinter as tk
import unittest
from unittest.mock import patch

from sarr_core.gui import launch_gui


class FakeRoot:
    def __init__(self) -> None:
        self.mainloop_called = False

    def mainloop(self) -> None:
        self.mainloop_called = True


class GuiTests(unittest.TestCase):
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
