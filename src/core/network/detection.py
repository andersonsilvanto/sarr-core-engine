"""Sliding-window detection of TCP port scans and SYN floods."""

import ipaddress
import math
import re
from collections import deque
from dataclasses import dataclass, field
from threading import RLock

from core.models import SecurityEvent
from core.network.config import DetectionConfig


_COMPACT_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}
_NAMED_FLAGS = frozenset(_COMPACT_FLAGS.values())


class TrackingCapacityError(RuntimeError):
    """Raised when a new source IP cannot be tracked without evicting active data."""


@dataclass
class _SourceWindow:
    last_seen: float
    last_packet_timestamp: float
    syn_timestamps: deque[float] = field(default_factory=deque)
    port_timestamps: dict[int, float] = field(default_factory=dict)
    last_emitted: dict[str, float] = field(default_factory=dict)


class HeuristicDetector:
    def __init__(self, config: DetectionConfig) -> None:
        if not isinstance(config, DetectionConfig):
            raise TypeError("config must be a DetectionConfig.")
        self._config = config
        self._allowlist = tuple(
            ipaddress.ip_network(entry, strict=False) for entry in config.allowlist
        )
        self._sources: dict[str, _SourceWindow] = {}
        self._watermark = float("-inf")
        self._lock = RLock()

    @property
    def tracked_ip_count(self) -> int:
        with self._lock:
            return len(self._sources)

    def observe_packet(
        self,
        *,
        src_ip: str,
        dst_port: int,
        flags: str,
        timestamp: float,
    ) -> tuple[SecurityEvent, ...]:
        source_ip = self._normalize_ip(src_ip)
        if (
            isinstance(dst_port, bool)
            or not isinstance(dst_port, int)
            or not 1 <= dst_port <= 65535
        ):
            raise ValueError("dst_port must be between 1 and 65535.")
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
        ):
            raise ValueError("timestamp must be a finite number.")
        normalized_flags = self._parse_flags(flags)

        with self._lock:
            self._watermark = max(self._watermark, float(timestamp))
            self._expire_inactive_sources(self._watermark)
            if self._is_allowlisted(source_ip):
                return ()
            state = self._sources.get(source_ip)
            if state is None:
                if float(timestamp) < self._watermark - self._config.inactive_timeout_seconds:
                    raise ValueError("Observation timestamp is outside the active window.")
                if len(self._sources) >= self._config.max_tracked_ips:
                    raise TrackingCapacityError(
                        "Maximum tracked source IP count has been reached."
                    )
                state = _SourceWindow(
                    last_seen=float(timestamp),
                    last_packet_timestamp=float(timestamp),
                )
                self._sources[source_ip] = state
            elif float(timestamp) < state.last_packet_timestamp:
                raise ValueError("Packet timestamps must be ordered for each source IP.")

            state.last_seen = max(state.last_seen, float(timestamp))
            state.last_packet_timestamp = float(timestamp)
            cutoff = float(timestamp) - self._config.window_seconds
            self._expire_window(state, cutoff)
            if "SYN" not in normalized_flags or "ACK" in normalized_flags:
                return ()

            state.syn_timestamps.append(float(timestamp))
            state.port_timestamps[dst_port] = float(timestamp)
            events: list[SecurityEvent] = []
            if len(state.port_timestamps) > self._config.port_scan_unique_ports:
                event = self._event_if_ready(
                    source_ip,
                    state,
                    "PORT_SCAN",
                    float(timestamp),
                    {
                        "unique_ports": len(state.port_timestamps),
                        "threshold": self._config.port_scan_unique_ports,
                        "window_seconds": self._config.window_seconds,
                    },
                )
                if event is not None:
                    events.append(event)

            syn_rate = len(state.syn_timestamps) / self._config.window_seconds
            if syn_rate > self._config.syn_flood_threshold_per_second:
                event = self._event_if_ready(
                    source_ip,
                    state,
                    "SYN_FLOOD",
                    float(timestamp),
                    {
                        "syn_count": len(state.syn_timestamps),
                        "rate_per_second": syn_rate,
                        "threshold_per_second": (
                            self._config.syn_flood_threshold_per_second
                        ),
                        "window_seconds": self._config.window_seconds,
                    },
                )
                if event is not None:
                    events.append(event)
            return tuple(events)

    @staticmethod
    def _normalize_ip(value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("src_ip must be a valid IP address.")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("src_ip must be a valid IP address.") from error

    @staticmethod
    def _parse_flags(value: str) -> frozenset[str]:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("flags must be a non-empty TCP flag value.")
        normalized = value.strip().upper()
        if re.fullmatch(r"0X[0-9A-F]+", normalized):
            bits = int(normalized, 16)
            return frozenset(
                flag_name
                for bit, flag_name in (
                    (0x01, "FIN"),
                    (0x02, "SYN"),
                    (0x04, "RST"),
                    (0x08, "PSH"),
                    (0x10, "ACK"),
                    (0x20, "URG"),
                    (0x40, "ECE"),
                    (0x80, "CWR"),
                    (0x100, "NS"),
                )
                if bits & bit
            )
        if all(letter in _COMPACT_FLAGS for letter in normalized):
            return frozenset(_COMPACT_FLAGS[letter] for letter in normalized)
        tokens = frozenset(
            token
            for token in re.split(r"[\s,|]+", normalized)
            if token
        )
        if not tokens.issubset(_NAMED_FLAGS):
            raise ValueError("flags must contain recognized TCP flag names.")
        return tokens

    def _is_allowlisted(self, source_ip: str) -> bool:
        address = ipaddress.ip_address(source_ip)
        return any(
            address.version == network.version and address in network
            for network in self._allowlist
        )

    def _expire_inactive_sources(self, timestamp: float) -> None:
        expiration = timestamp - self._config.inactive_timeout_seconds
        expired = [
            source_ip
            for source_ip, state in self._sources.items()
            if state.last_seen < expiration
        ]
        for source_ip in expired:
            del self._sources[source_ip]

    def _expire_window(self, state: _SourceWindow, cutoff: float) -> None:
        while state.syn_timestamps and state.syn_timestamps[0] < cutoff:
            state.syn_timestamps.popleft()
        expired_ports = [
            port
            for port, timestamp in state.port_timestamps.items()
            if timestamp < cutoff
        ]
        for port in expired_ports:
            del state.port_timestamps[port]

    def _event_if_ready(
        self,
        source_ip: str,
        state: _SourceWindow,
        kind: str,
        timestamp: float,
        details: dict[str, object],
    ) -> SecurityEvent | None:
        previous = state.last_emitted.get(kind)
        if (
            previous is not None
            and timestamp - previous < self._config.cooldown_seconds
        ):
            return None
        state.last_emitted[kind] = timestamp
        return SecurityEvent(
            timestamp=timestamp,
            src_ip=source_ip,
            kind=kind,
            severity=8,
            details=details,
        )
