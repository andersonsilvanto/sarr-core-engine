"""Shared immutable security event models."""

import ipaddress
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: float
    src_ip: str | None
    kind: str
    severity: int
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, (int, float))
            or not math.isfinite(self.timestamp)
        ):
            raise ValueError("timestamp must be a finite number.")
        if self.src_ip is not None:
            if not isinstance(self.src_ip, str):
                raise TypeError("src_ip must be a valid IP address or None.")
            try:
                normalized_ip = str(ipaddress.ip_address(self.src_ip))
            except ValueError as error:
                raise ValueError("src_ip must be a valid IP address or None.") from error
            object.__setattr__(self, "src_ip", normalized_ip)
        if not isinstance(self.kind, str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,63}", self.kind
        ):
            raise ValueError("kind must be a non-empty uppercase identifier.")
        if isinstance(self.severity, bool) or not isinstance(self.severity, int):
            raise TypeError("severity must be an integer.")
        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a mapping.")
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))
