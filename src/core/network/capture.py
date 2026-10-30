"""Capture sources that provide extracted TCP metadata to the detector."""

import ipaddress
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Protocol


_MAX_CAPTURE_BYTES = 25_000_000
_MAX_TSHARK_OUTPUT_BYTES = 2_000_000
_MAX_CAPTURE_PACKETS = 10_000
_TCP_FLAG_BITS = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
    (0x40, "E"),
    (0x80, "C"),
    (0x100, "N"),
)


@dataclass(frozen=True)
class PacketObservation:
    src_ip: str
    dst_port: int
    flags: str
    timestamp: float

    def __post_init__(self) -> None:
        if not isinstance(self.src_ip, str):
            raise TypeError("src_ip must be a valid IP address.")
        try:
            normalized_ip = str(ipaddress.ip_address(self.src_ip))
        except ValueError as error:
            raise ValueError("src_ip must be a valid IP address.") from error
        object.__setattr__(self, "src_ip", normalized_ip)
        if (
            isinstance(self.dst_port, bool)
            or not isinstance(self.dst_port, int)
            or not 1 <= self.dst_port <= 65535
        ):
            raise ValueError("dst_port must be between 1 and 65535.")
        if not isinstance(self.flags, str) or not self.flags.strip():
            raise ValueError("flags must be a non-empty TCP flag value.")
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, (int, float))
            or not math.isfinite(self.timestamp)
        ):
            raise ValueError("timestamp must be a finite number.")


class CaptureSource(Protocol):
    def __iter__(self) -> Iterator[PacketObservation]: ...


class SyntheticCaptureSource:
    """Yield caller-provided synthetic packet observations without networking."""

    def __init__(self, observations: Iterable[PacketObservation]) -> None:
        self._observations = tuple(observations)
        if any(not isinstance(item, PacketObservation) for item in self._observations):
            raise TypeError("Synthetic observations must be PacketObservation values.")

    def __iter__(self) -> Iterator[PacketObservation]:
        return iter(self._observations)


class PcapCaptureSource:
    """Extract bounded TCP metadata from a project-local offline capture."""

    def __init__(
        self,
        capture_path: str | Path,
        *,
        project_root: str | Path,
        tshark_executable: str | Path,
    ) -> None:
        self._project_root = Path(project_root).resolve()
        self._capture_path = Path(capture_path).resolve(strict=True)
        self._tshark_executable = str(tshark_executable)
        try:
            self._capture_path.relative_to(self._project_root)
        except ValueError as error:
            raise ValueError("Capture files must remain inside the project directory.") from error
        if self._capture_path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("Only .pcap and .pcapng capture files are supported.")
        if (
            not self._capture_path.is_file()
            or self._capture_path.stat().st_size > _MAX_CAPTURE_BYTES
        ):
            raise ValueError("Capture is missing or exceeds the supported size limit.")
        if not self._tshark_executable:
            raise ValueError("A Tshark executable must be specified.")

    def __iter__(self) -> Iterator[PacketObservation]:
        result = subprocess.run(
            [
                self._tshark_executable,
                "-r",
                str(self._capture_path),
                "-T",
                "fields",
                "-E",
                "separator=\\t",
                "-c",
                str(_MAX_CAPTURE_PACKETS),
                "-e",
                "frame.time_epoch",
                "-e",
                "ip.src",
                "-e",
                "ipv6.src",
                "-e",
                "tcp.dstport",
                "-e",
                "tcp.flags",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            shell=False,
        )
        output = result.stdout.encode("utf-8", errors="replace")
        if len(output) > _MAX_TSHARK_OUTPUT_BYTES:
            raise RuntimeError("Tshark output exceeded the supported size limit.")
        if result.returncode != 0:
            raise RuntimeError("Tshark could not analyze the offline capture.")
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 5:
                raise RuntimeError("Tshark returned an invalid packet record.")
            timestamp_text, ipv4_src, ipv6_src, port_text, flags_text = fields
            src_ip = ipv4_src or ipv6_src
            if not src_ip or not port_text or not flags_text:
                continue
            try:
                timestamp = float(timestamp_text)
                dst_port = int(port_text)
                flag_bits = int(flags_text, 0)
            except ValueError as error:
                raise RuntimeError("Tshark returned invalid TCP metadata.") from error
            flags = "".join(
                letter
                for bit, letter in _TCP_FLAG_BITS
                if flag_bits & bit
            )
            yield PacketObservation(
                src_ip=src_ip,
                dst_port=dst_port,
                flags=flags or "-",
                timestamp=timestamp,
            )
