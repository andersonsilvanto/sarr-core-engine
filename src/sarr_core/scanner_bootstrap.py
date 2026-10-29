"""Discover local scanner binaries and provide safe, manual setup guidance."""

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


_SCANNERS = {
    "nmap": ("nmap", "Insecure.Nmap"),
    "tshark": ("tshark", "WiresharkFoundation.Wireshark"),
}


@dataclass(frozen=True)
class ScannerInstallation:
    name: str
    executable: Path | None
    package_id: str

    @property
    def available(self) -> bool:
        return self.executable is not None


class ScannerBootstrap:
    """Find Nmap/Tshark locally; never download or install packages itself."""

    def inspect(self) -> tuple[ScannerInstallation, ...]:
        return tuple(self.locate(name) for name in _SCANNERS)

    def locate(self, name: str) -> ScannerInstallation:
        key = name.lower()
        if key not in _SCANNERS:
            raise ValueError(f"Unsupported scanner: {name!r}")

        executable_name, package_id = _SCANNERS[key]
        executable = shutil.which(executable_name)
        if executable is not None:
            return ScannerInstallation(key, Path(executable), package_id)

        for candidate in self._standard_windows_paths(key):
            if candidate.is_file():
                return ScannerInstallation(key, candidate, package_id)
        return ScannerInstallation(key, None, package_id)

    @staticmethod
    def _standard_windows_paths(name: str) -> tuple[Path, ...]:
        if sys.platform != "win32":
            return ()

        program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        program_files_x86 = Path(
            os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")
        )
        if name == "nmap":
            return (
                program_files / "Nmap" / "nmap.exe",
                program_files_x86 / "Nmap" / "nmap.exe",
            )
        return (program_files / "Wireshark" / "tshark.exe",)

    @staticmethod
    def installation_guidance(
        installations: tuple[ScannerInstallation, ...],
    ) -> tuple[str, ...]:
        missing = [item for item in installations if not item.available]
        if not missing:
            return ()
        commands = tuple(
            f"winget install --id {item.package_id} --exact --source winget"
            for item in missing
        )
        return (
            "Instalação assistida (manual): confira o editor e os termos do pacote "
            "antes de executar estes comandos em um terminal confiável:",
            *commands,
            "O SARR-Core não baixa nem executa instaladores. Após a instalação, "
            "reinicie o aplicativo para atualizar o PATH.",
        )


__all__ = ["ScannerBootstrap", "ScannerInstallation"]
