"""Reproducible telemetry scenarios and an HTTP demo server bound to loopback."""

import json
import math
import random
import time
from dataclasses import dataclass
from enum import Enum


class TelemetryScenario(Enum):
    NORMAL_LATENCY = "normal_latency"
    HIGH_RTT = "high_rtt"
    HIGH_5XX_RATE = "high_5xx_rate"
    MISSING_TELEMETRY = "missing_telemetry"
    MANUAL_INTERRUPTION = "manual_interruption"


@dataclass(frozen=True)
class TelemetrySample:
    cpu_percent: float
    ram_percent: float
    rtt_ms: float
    drop_rate: float

    def __post_init__(self) -> None:
        values = (
            self.cpu_percent,
            self.ram_percent,
            self.rtt_ms,
            self.drop_rate,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in values
        ):
            raise ValueError("Telemetry values must be finite numbers.")
        if not 0 <= self.cpu_percent <= 100:
            raise ValueError("cpu_percent must be between 0 and 100.")
        if not 0 <= self.ram_percent <= 100:
            raise ValueError("ram_percent must be between 0 and 100.")
        if self.rtt_ms < 0:
            raise ValueError("rtt_ms must be non-negative.")
        if not 0 <= self.drop_rate <= 1:
            raise ValueError("drop_rate must be between 0 and 1.")

    def to_json(self) -> dict[str, float]:
        return {
            "cpu_percent": self.cpu_percent,
            "ram_percent": self.ram_percent,
            "rtt_ms": self.rtt_ms,
            "drop_rate": self.drop_rate,
        }

    @classmethod
    def from_json(cls, value: object) -> "TelemetrySample":
        if not isinstance(value, dict):
            raise ValueError("Telemetry response must be a JSON object.")
        try:
            fields = (
                value["cpu_percent"],
                value["ram_percent"],
                value["rtt_ms"],
                value["drop_rate"],
            )
            if any(
                isinstance(field, bool) or not isinstance(field, (int, float))
                for field in fields
            ):
                raise ValueError("Telemetry fields must be JSON numbers.")
            return cls(
                cpu_percent=float(fields[0]),
                ram_percent=float(fields[1]),
                rtt_ms=float(fields[2]),
                drop_rate=float(fields[3]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Telemetry response is incomplete or invalid.") from error


class TelemetrySimulator:
    def __init__(self, *, seed: int = 0) -> None:
        self._random = random.Random(seed)

    def sample(self, scenario: TelemetryScenario) -> TelemetrySample | None:
        if not isinstance(scenario, TelemetryScenario):
            raise TypeError("scenario must be a TelemetryScenario.")
        if scenario is TelemetryScenario.MISSING_TELEMETRY:
            return None
        rtt_ms = (
            1501.0
            if scenario is TelemetryScenario.HIGH_RTT
            else round(self._random.uniform(15.0, 120.0), 2)
        )
        return TelemetrySample(
            cpu_percent=round(self._random.uniform(10.0, 85.0), 2),
            ram_percent=round(self._random.uniform(20.0, 90.0), 2),
            rtt_ms=rtt_ms,
            drop_rate=round(self._random.uniform(0.0, 0.05), 4),
        )


def encode_response(
    scenario: TelemetryScenario,
    sample: TelemetrySample | None,
    request_number: int,
) -> tuple[int, bytes, float]:
    status_code = 200
    delay_seconds = 0.0
    if scenario is TelemetryScenario.HIGH_RTT:
        delay_seconds = 1.51
    elif (
        scenario is TelemetryScenario.HIGH_5XX_RATE
        and request_number % 5 == 0
    ):
        status_code = 503

    payload = {
        "manual_interruption": (
            scenario is TelemetryScenario.MANUAL_INTERRUPTION
        ),
        "scenario": scenario.value,
        "telemetry": sample.to_json() if sample is not None else None,
    }
    return (
        status_code,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        delay_seconds,
    )


def delay_for_response(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)
