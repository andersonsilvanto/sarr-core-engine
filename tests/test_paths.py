import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import core.paths
from core.paths import (
    DataDirectoryError,
    default_user_data_directory,
    resolve_data_directory,
)


class DataDirectoryTests(unittest.TestCase):
    def test_linux_user_data_path_uses_xdg_environment(self) -> None:
        with patch.object(core.paths.sys, "platform", "linux"), patch.dict(
            "os.environ",
            {"XDG_DATA_HOME": str(Path("relative-data"))},
            clear=True,
        ):
            self.assertEqual(
                default_user_data_directory(),
                Path("relative-data") / "sarr-core" / "data",
            )

    def test_windows_user_data_path_uses_local_app_data(self) -> None:
        with patch.object(core.paths.sys, "platform", "win32"), patch.dict(
            "os.environ",
            {"LOCALAPPDATA": str(Path("local-data"))},
            clear=True,
        ):
            self.assertEqual(
                default_user_data_directory(),
                Path("local-data") / "SARR-Core" / "data",
            )

    def test_portable_flag_selects_local_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app_directory = Path(temporary) / "app"
            app_directory.mkdir()
            (app_directory / "portable.flag").touch()
            user_directory = Path(temporary) / "user-data"

            selected = resolve_data_directory(
                app_directory=app_directory,
                user_data_directory=user_directory,
            )

            self.assertEqual(selected, app_directory / "data")
            self.assertTrue(selected.is_dir())
            self.assertEqual(list(selected.iterdir()), [])
            self.assertFalse(user_directory.exists())

    def test_unwritable_portable_directory_falls_back_to_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app_directory = Path(temporary) / "app"
            app_directory.mkdir()
            (app_directory / "portable.flag").touch()
            (app_directory / "data").write_text("not a directory", encoding="utf-8")
            user_directory = Path(temporary) / "user-data"

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                selected = resolve_data_directory(
                    app_directory=app_directory,
                    user_data_directory=user_directory,
                )

            self.assertEqual(selected, user_directory)
            self.assertTrue(caught)
            self.assertTrue(any("per-user" in str(item.message) for item in caught))

    def test_fails_closed_when_portable_and_fallback_paths_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app_directory = Path(temporary) / "app"
            app_directory.mkdir()
            (app_directory / "portable.flag").touch()
            (app_directory / "data").write_text("not a directory", encoding="utf-8")
            user_directory = Path(temporary) / "user-data"
            user_directory.write_text("not a directory", encoding="utf-8")

            with self.assertRaises(DataDirectoryError):
                resolve_data_directory(
                    app_directory=app_directory,
                    user_data_directory=user_directory,
                )


if __name__ == "__main__":
    unittest.main()
