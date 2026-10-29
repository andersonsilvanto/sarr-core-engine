"""Bounded local HTTP telemetry server for controlled resilience tests."""

from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from threading import Thread

from core.telemetry import (
    TelemetryScenario,
    TelemetrySimulator,
    delay_for_response,
    encode_response,
)


class _LoopbackHTTPServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 8


class LocalDemoServer(AbstractContextManager["LocalDemoServer"]):
    MAX_REQUESTS = 100

    def __init__(
        self,
        scenario: TelemetryScenario,
        *,
        seed: int = 0,
        host: str = "127.0.0.1",
        port: int = 0,
        max_requests: int = 20,
    ) -> None:
        try:
            parsed_host = ip_address(host)
        except ValueError as error:
            raise ValueError("Demo server host must be the literal 127.0.0.1.") from error
        if not parsed_host.is_loopback or parsed_host.version != 4 or host != "127.0.0.1":
            raise ValueError("Demo server is restricted to 127.0.0.1.")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("port must be 0 (ephemeral) or a valid TCP port.")
        if (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or not 1 <= max_requests <= self.MAX_REQUESTS
        ):
            raise ValueError(f"max_requests must be between 1 and {self.MAX_REQUESTS}.")
        if not isinstance(scenario, TelemetryScenario):
            raise TypeError("scenario must be a TelemetryScenario.")
        self.scenario = scenario
        simulator = TelemetrySimulator(seed=seed)
        self._request_count = 0

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self) -> None:
                if self.path != "/telemetry":
                    self.send_error(404)
                    return
                owner._request_count += 1
                if owner._request_count > max_requests:
                    self.send_error(429)
                    return
                sample = simulator.sample(scenario)
                status_code, body, delay_seconds = encode_response(
                    scenario, sample, owner._request_count
                )
                delay_for_response(delay_seconds)
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_connection_close()
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def send_connection_close(self) -> None:
                self.send_header("Connection", "close")

        owner = self
        self._server = _LoopbackHTTPServer((host, port), Handler)
        if self._server.server_address[0] != "127.0.0.1":
            self._server.server_close()
            raise RuntimeError("Demo server did not bind to the required loopback.")
        self._thread = Thread(
            target=self._server.serve_forever,
            name="sarr-local-demo-server",
            daemon=True,
        )
        self._started = False

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def request_count(self) -> int:
        return self._request_count

    def start(self) -> "LocalDemoServer":
        if self._started:
            raise RuntimeError("Demo server is already running.")
        self._thread.start()
        self._started = True
        return self

    def close(self) -> None:
        if self._started:
            self._server.shutdown()
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise RuntimeError("Demo server did not shut down cleanly.")
            self._started = False
        self._server.server_close()

    def __enter__(self) -> "LocalDemoServer":
        return self.start()

    def __exit__(
        self, _exc_type: object, _exc: object, _traceback: object
    ) -> bool:
        self.close()
        return False
