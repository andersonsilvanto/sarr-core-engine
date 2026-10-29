"""Resolve a writable persistent data directory with portable-mode fallback."""

import os
import sys
import tempfile
import warnings
from pathlib import Path


class DataDirectoryError(RuntimeError):
    """Raised when no persistent writable data directory can be selected."""


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def default_user_data_directory() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "SARR-Core" / "data"
    return Path.home() / "AppData" / "Local" / "SARR-Core" / "data"


def _ensure_writable_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if not directory.is_dir():
        raise OSError(f"Data path is not a directory: {directory}")
    handle, probe_path = tempfile.mkstemp(
        prefix=".sarr-write-test-",
        dir=directory,
    )
    try:
        with os.fdopen(handle, "wb") as probe:
            probe.write(b"write-test")
            probe.flush()
            os.fsync(probe.fileno())
    finally:
        Path(probe_path).unlink(missing_ok=True)


def resolve_data_directory(
    *,
    app_directory: str | Path | None = None,
    user_data_directory: str | Path | None = None,
) -> Path:
    """Select data/ beside the app in portable mode, else per-user storage.

    An unwritable portable directory falls back to the persistent per-user
    directory. If that path is also unavailable, fail rather than losing data.
    """
    app_root = Path(app_directory) if app_directory is not None else application_directory()
    user_root = (
        Path(user_data_directory)
        if user_data_directory is not None
        else default_user_data_directory()
    )
    portable_data = app_root / "data"

    if (app_root / "portable.flag").is_file():
        try:
            _ensure_writable_directory(portable_data)
            return portable_data
        except OSError as portable_error:
            try:
                _ensure_writable_directory(user_root)
            except OSError as fallback_error:
                raise DataDirectoryError(
                    "Portable data directory is not writable and the per-user "
                    f"fallback also failed: {user_root}"
                ) from fallback_error
            warnings.warn(
                "Portable data directory is not writable; using the per-user "
                f"data directory instead: {user_root}. Cause: {portable_error}",
                RuntimeWarning,
                stacklevel=2,
            )
            return user_root

    try:
        _ensure_writable_directory(user_root)
    except OSError as error:
        raise DataDirectoryError(
            f"Could not create or write to the per-user data directory: {user_root}"
        ) from error
    return user_root
