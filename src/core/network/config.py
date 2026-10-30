"""Validated configuration for network heuristic detection."""

import json
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}.")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise ValueError(f"Invalid JSON numeric constant: {value}.")


@dataclass(frozen=True)
class DetectionConfig:
    port_scan_unique_ports: int
    window_seconds: float
    syn_flood_threshold_per_second: float
    max_tracked_ips: int
    max_blocked_ips: int
    inactive_timeout_seconds: float
    cooldown_seconds: float
    allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        positive_numbers = {
            "window_seconds": self.window_seconds,
            "syn_flood_threshold_per_second": self.syn_flood_threshold_per_second,
            "inactive_timeout_seconds": self.inactive_timeout_seconds,
        }
        for field_name, value in positive_numbers.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
            ):
                raise ValueError(f"{field_name} must be a positive number.")
        integer_limits = {
            "port_scan_unique_ports": (self.port_scan_unique_ports, 1, 65535),
            "max_tracked_ips": (self.max_tracked_ips, 1, None),
            "max_blocked_ips": (self.max_blocked_ips, 1, None),
        }
        for field_name, (value, minimum, maximum) in integer_limits.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < minimum
                or (maximum is not None and value > maximum)
            ):
                raise ValueError(f"{field_name} is outside its supported range.")
        if (
            isinstance(self.cooldown_seconds, bool)
            or not isinstance(self.cooldown_seconds, (int, float))
            or self.cooldown_seconds < 0
        ):
            raise ValueError("cooldown_seconds must be a non-negative number.")
        if self.inactive_timeout_seconds < self.window_seconds:
            raise ValueError(
                "inactive_timeout_seconds must be at least window_seconds."
            )
        if not isinstance(self.allowlist, tuple):
            raise TypeError("allowlist must be a tuple of IP addresses or networks.")
        for item in self.allowlist:
            if not isinstance(item, str):
                raise TypeError("allowlist entries must be strings.")
            try:
                ip_network(item, strict=False)
            except ValueError as error:
                raise ValueError(f"Invalid allowlist network: {item!r}.") from error

    @classmethod
    def from_json_file(
        cls,
        config_path: str | Path | None = None,
        *,
        schema_path: str | Path | None = None,
    ) -> "DetectionConfig":
        project_root = Path(__file__).resolve().parents[3]
        source_path = (
            Path(config_path)
            if config_path is not None
            else project_root / "config" / "network_detection.json"
        )
        schema_file = (
            Path(schema_path)
            if schema_path is not None
            else project_root / "schemas" / "network_detection.schema.json"
        )
        try:
            document = json.loads(
                source_path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
            schema = json.loads(
                schema_file.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("Detection configuration or schema is invalid.") from error
        try:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(document)
        except ValidationError as error:
            raise ValueError(
                f"Detection configuration does not match its schema: {error.message}"
            ) from error
        if not isinstance(document, dict):
            raise ValueError("Detection configuration must be a JSON object.")
        return cls(
            port_scan_unique_ports=document["port_scan_unique_ports"],
            window_seconds=document["window_seconds"],
            syn_flood_threshold_per_second=document[
                "syn_flood_threshold_per_second"
            ],
            max_tracked_ips=document["max_tracked_ips"],
            max_blocked_ips=document["max_blocked_ips"],
            inactive_timeout_seconds=document["inactive_timeout_seconds"],
            cooldown_seconds=document["cooldown_seconds"],
            allowlist=tuple(document["allowlist"]),
        )
