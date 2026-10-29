import unittest
from pathlib import Path

from sarr_core.cli import build_parser


ROOT = Path(__file__).resolve().parents[1]


class ReleaseReadinessTests(unittest.TestCase):
    def test_cli_allows_export_commands_without_status_or_simulation(self) -> None:
        empty = build_parser().parse_args([])
        self.assertFalse(empty.status)
        self.assertFalse(empty.run_sim)
        self.assertTrue(build_parser().parse_args(["--run-sim"]).run_sim)
        self.assertTrue(build_parser().parse_args(["--gui"]).gui)
        self.assertTrue(build_parser().parse_args(["--status"]).status)
        metadata = build_parser().parse_args(["--export-metadata"])
        self.assertTrue(metadata.export_metadata)
        dashboard = build_parser().parse_args(["--export-dashboard"])
        self.assertTrue(dashboard.export_dashboard)
        combined = build_parser().parse_args(
            ["--status", "--export-metadata", "--export-dashboard"]
        )
        self.assertTrue(combined.status)
        self.assertTrue(combined.export_metadata)
        self.assertTrue(combined.export_dashboard)

    def test_status_and_simulation_remain_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--status", "--run-sim"])

    def test_windows_scripts_use_virtual_environment_and_simulation(self) -> None:
        setup_script = (ROOT / "scripts" / "setup_windows.bat").read_text(
            encoding="utf-8"
        )
        run_script = (ROOT / "scripts" / "run_windows.bat").read_text(
            encoding="utf-8"
        )

        self.assertIn('.venv\\Scripts\\python.exe', setup_script)
        self.assertIn('--require-hashes -r requirements-lock.txt', setup_script)
        self.assertIn('discover -s tests -p "*test*.py" -v', setup_script)
        self.assertIn('.venv\\Scripts\\python.exe', run_script)
        self.assertIn('-m sarr_core --run-sim', run_script)
        self.assertNotIn('-m sarr_core\n', run_script)


if __name__ == "__main__":
    unittest.main()
