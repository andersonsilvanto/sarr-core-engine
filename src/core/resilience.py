"""Loopback-only telemetry probes and a kill-switch-coupled circuit breaker."""

import http.client
import json
import time
from enum import Enum
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID

from core.audit import Persistence
from core.events import Event, EventBus
from core.kill_switch import KillSwitch, KillSwitchEvent, KillSwitchTriggered
from core.operational_limits import OperationalLimitEnforcer, OperationalLimitExceeded
from core.telemetry import TelemetrySample


class CircuitOpenError(RuntimeError):
    """Raised when a probe is attempted after the circuit breaker has opened."""


class TelemetryUnavailable(RuntimeError):
    """Raised when the demo endpoint returns missing or invalid telemetry."""


class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"


ResultT = TypeVar("ResultT")


class SafetyCircuitBreaker:
    def __init__(
        self,
        kill_switch: KillSwitch,
        *,
        run_id: UUID,
        failure_threshold: int = 3,
    ) -> None:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        if (
            isinstance(failure_threshold, bool)
            or not isinstance(failure_threshold, int)
            or failure_threshold < 1
        ):
            raise ValueError("failure_threshold must be a positive integer.")
        self._kill_switch = kill_switch
        self._run_id = run_id
        self._failure_threshold = failure_threshold
        self._failure_count = 0
        self._state = CircuitState.OPEN if kill_switch.is_triggered else CircuitState.CLOSED
        self._lock = RLock()
        self._kill_switch.subscribe(self._on_kill_switch)

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state

    def execute(self, operation: Callable[[], ResultT]) -> ResultT:
        self.assert_closed()
        try:
            result = operation()
        except Exception:
            with self._lock:
                self._failure_count += 1
                should_trip = self._failure_count >= self._failure_threshold
            if should_trip and not self._kill_switch.is_triggered:
                self._kill_switch.trigger(
                    "Circuit breaker failure threshold reached.",
                    reason_code="circuit_breaker_failure",
                    run_id=self._run_id,
                )
            raise
        with self._lock:
            self._failure_count = 0
        return result

    def assert_closed(self) -> None:
        if self._kill_switch.is_triggered:
            with self._lock:
                self._state = CircuitState.OPEN
        if self.state is CircuitState.OPEN:
            raise CircuitOpenError("Circuit breaker is open.")

    def _on_kill_switch(self, _event: KillSwitchEvent) -> None:
        with self._lock:
            self._state = CircuitState.OPEN


class LocalTelemetryProbe:
    HOST = "127.0.0.1"
    PATH = "/telemetry"
    TIMEOUT_SECONDS = 5.0
    MAX_RESPONSE_BYTES = 16_384

    def __init__(
        self,
        *,
        port: int,
        run_id: UUID,
        limits: OperationalLimitEnforcer,
        kill_switch: KillSwitch,
        event_bus: EventBus | None = None,
        persistence: Persistence | None = None,
    ) -> None:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError("port must be a valid loopback TCP port.")
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        self._port = port
        self._run_id = run_id
        self._limits = limits
        self._kill_switch = kill_switch
        self._event_bus = event_bus or EventBus()
        self._persistence = persistence
        if persistence is not None:
            persistence.attach(self._event_bus)
        self._circuit_breaker = SafetyCircuitBreaker(
            kill_switch,
            run_id=run_id,
        )

    @property
    def circuit_breaker(self) -> SafetyCircuitBreaker:
        return self._circuit_breaker

    @property
    def request_host(self) -> str:
        return self.HOST

    def sample(self) -> TelemetrySample:
        return self._circuit_breaker.execute(self._sample_once)

    def interrupt(self) -> None:
        self._kill_switch.trigger(
            "Manual interruption requested.",
            reason_code="manual_interruption",
            run_id=self._run_id,
        )
        raise KillSwitchTriggered("Manual interruption requested.")

    def _sample_once(self) -> TelemetrySample:
        with self._limits.begin_operation():
            started = time.perf_counter()
            status_code, body = self._request_local()
            rtt_ms = (time.perf_counter() - started) * 1000
            try:
                response = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                self._trip("Invalid local telemetry JSON.", "telemetry_invalid")
                raise TelemetryUnavailable("Invalid local telemetry JSON.") from error
            if not isinstance(response, dict):
                self._trip("Invalid local telemetry response.", "telemetry_invalid")
                raise TelemetryUnavailable("Invalid local telemetry response.")
            if response.get("manual_interruption") is True:
                self.interrupt()
            try:
                sample = TelemetrySample.from_json(response.get("telemetry"))
            except ValueError as error:
                reason_code = (
                    "telemetry_missing"
                    if response.get("telemetry") is None
                    else "telemetry_invalid"
                )
                self._trip("Telemetry is missing or invalid.", reason_code)
                raise TelemetryUnavailable(
                    "Telemetry is missing or invalid."
                ) from error

            try:
                self._limits.record_result(
                    rtt_ms=rtt_ms,
                    status_code=status_code,
                    volume_bytes=len(body),
                )
            except OperationalLimitExceeded:
                raise
            self._publish_sample(sample, rtt_ms, status_code, len(body))
            return TelemetrySample(
                cpu_percent=sample.cpu_percent,
                ram_percent=sample.ram_percent,
                rtt_ms=rtt_ms,
                drop_rate=sample.drop_rate,
            )

    def _request_local(self) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(
            self.HOST,
            self._port,
            timeout=self.TIMEOUT_SECONDS,
        )
        try:
            connection.request("GET", self.PATH, headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(self.MAX_RESPONSE_BYTES + 1)
            if len(body) > self.MAX_RESPONSE_BYTES:
                self._trip("Local telemetry response too large.", "response_too_large")
                raise TelemetryUnavailable("Local telemetry response too large.")
            return response.status, body
        except (OSError, http.client.HTTPException) as error:
            self._trip("Local telemetry endpoint unavailable.", "local_demo_unavailable")
            raise TelemetryUnavailable(
                "Local telemetry endpoint unavailable."
            ) from error
        finally:
            connection.close()

    def _publish_sample(
        self,
        sample: TelemetrySample,
        rtt_ms: float,
        status_code: int,
        volume_bytes: int,
    ) -> None:
        payload: dict[str, object] = {
            "metric": "telemetry",
            "value": sample.cpu_percent,
            "unit": "percent",
            "cpu_percent": sample.cpu_percent,
            "ram_percent": sample.ram_percent,
            "rtt_ms": rtt_ms,
            "drop_rate": sample.drop_rate,
            "status_code": status_code,
            "volume_bytes": volume_bytes,
        }
        event = Event(
            run_id=self._run_id,
            name="metric.sample",
            payload=payload,
        )
        if self._persistence is None:
            self._event_bus.publish(event)
            return

        with self._persistence.database.transaction():
            for name, value, unit in (
                ("cpu_percent", sample.cpu_percent, "percent"),
                ("ram_percent", sample.ram_percent, "percent"),
                ("rtt_ms", rtt_ms, "ms"),
                ("drop_rate", sample.drop_rate, "ratio"),
            ):
                self._persistence.metrics.create(
                    self._run_id,
                    name,
                    value,
                    unit=unit,
                )
            self._event_bus.publish(event)

    def _trip(self, reason: str, reason_code: str) -> None:
        self._kill_switch.trigger(
            reason,
            reason_code=reason_code,
            run_id=self._run_id,
        )
