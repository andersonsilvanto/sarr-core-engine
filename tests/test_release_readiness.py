import unittest
from pathlib import Path

from sarr_core.cli import build_parser


ROOT = Path(__file__).resolve().parents[1]


class ReleaseReadinessTests(unittest.TestCase):
    def test_cli_requires_explicit_status_or_simulation_command(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])

        self.assertTrue(build_parser().parse_args(["--run-sim"]).run_sim)
        self.assertTrue(build_parser().parse_args(["--status"]).status)

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
