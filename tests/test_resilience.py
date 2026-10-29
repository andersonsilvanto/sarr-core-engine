import json
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from core import (
    CircuitOpenError,
    CircuitState,
    KillSwitch,
    KillSwitchTriggered,
    LocalDemoServer,
    LocalTelemetryProbe,
    OperationalLimitEnforcer,
    OperationalLimitExceeded,
    Persistence,
    ScopeLimits,
    TelemetryScenario,
    TelemetrySimulator,
    TelemetryUnavailable,
)
from core.kill_switch import KillSwitchTriggered


class LocalTelemetryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = uuid4()
        self.kill_switch = KillSwitch()
        self.limits = ScopeLimits(
            max_duration_seconds=60,
            max_rate_per_second=20,
            max_concurrency=1,
            max_volume_bytes=100_000,
            measurement_window_seconds=10,
        )
        self.enforcer = OperationalLimitEnforcer(
            self.run_id,
            self.limits,
            self.kill_switch,
        )
        self.enforcer.start()

    def make_probe(self, port: int) -> LocalTelemetryProbe:
        return LocalTelemetryProbe(
            port=port,
            run_id=self.run_id,
            limits=self.enforcer,
            kill_switch=self.kill_switch,
        )

    def test_normal_telemetry_is_sampled_from_loopback(self) -> None:
        with LocalDemoServer(TelemetryScenario.NORMAL_LATENCY) as server:
            probe = self.make_probe(server.port)
            sample = probe.sample()

            self.assertEqual(probe.request_host, "127.0.0.1")
            self.assertGreaterEqual(sample.cpu_percent, 0)
            self.assertLessEqual(sample.cpu_percent, 100)
            self.assertGreaterEqual(sample.ram_percent, 0)
            self.assertLessEqual(sample.ram_percent, 100)
            self.assertGreaterEqual(sample.rtt_ms, 0)
            self.assertFalse(self.kill_switch.is_triggered)
            self.assertEqual(probe.circuit_breaker.state, CircuitState.CLOSED)
            self.assertEqual(server.request_count, 1)

    def test_high_rtt_trips_kill_switch_and_opens_circuit(self) -> None:
        with LocalDemoServer(TelemetryScenario.HIGH_RTT) as server:
            probe = self.make_probe(server.port)
            with self.assertRaises(OperationalLimitExceeded):
                probe.sample()

            self.assertTrue(self.kill_switch.is_triggered)
            self.assertEqual(self.kill_switch.event.reason_code, "rtt_limit")
            self.assertEqual(probe.circuit_breaker.state, CircuitState.OPEN)
            with self.assertRaises(CircuitOpenError):
                probe.sample()
            self.assertEqual(server.request_count, 1)

    def test_high_5xx_rate_trips_after_ten_local_responses(self) -> None:
        with LocalDemoServer(TelemetryScenario.HIGH_5XX_RATE) as server:
            probe = self.make_probe(server.port)
            for _ in range(9):
                probe.sample()

            with self.assertRaises(OperationalLimitExceeded):
                probe.sample()

            self.assertTrue(self.kill_switch.is_triggered)
            self.assertEqual(self.kill_switch.event.reason_code, "http_5xx_limit")
            self.assertEqual(probe.circuit_breaker.state, CircuitState.OPEN)
            self.assertEqual(server.request_count, 10)
            with self.assertRaises(CircuitOpenError):
                probe.sample()
            self.assertEqual(server.request_count, 10)

    def test_missing_telemetry_fails_closed(self) -> None:
        with LocalDemoServer(TelemetryScenario.MISSING_TELEMETRY) as server:
            probe = self.make_probe(server.port)
            with self.assertRaises(TelemetryUnavailable):
                probe.sample()

            self.assertTrue(self.kill_switch.is_triggered)
            self.assertEqual(
                self.kill_switch.event.reason_code,
                "telemetry_missing",
            )
            with self.assertRaises(CircuitOpenError):
                probe.sample()
            self.assertEqual(server.request_count, 1)

    def test_manual_interruption_latches_kill_switch_and_circuit(self) -> None:
        with LocalDemoServer(TelemetryScenario.MANUAL_INTERRUPTION) as server:
            probe = self.make_probe(server.port)
            with self.assertRaisesRegex(
                KillSwitchTriggered, "Manual interruption"
            ):
                probe.sample()

            self.assertTrue(self.kill_switch.is_triggered)
            self.assertEqual(
                self.kill_switch.event.reason_code,
                "manual_interruption",
            )
            self.assertEqual(probe.circuit_breaker.state, CircuitState.OPEN)
            with self.assertRaises(CircuitOpenError):
                probe.sample()
            self.assertEqual(server.request_count, 1)

    def test_demo_server_refuses_non_loopback_bind_addresses(self) -> None:
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            LocalDemoServer(TelemetryScenario.NORMAL_LATENCY, host="0.0.0.0")

    def test_telemetry_simulator_is_reproducible_with_same_seed(self) -> None:
        first = TelemetrySimulator(seed=42)
        second = TelemetrySimulator(seed=42)

        self.assertEqual(
            first.sample(TelemetryScenario.NORMAL_LATENCY),
            second.sample(TelemetryScenario.NORMAL_LATENCY),
        )

    def test_probe_persists_numeric_metrics_and_audit_event(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        persistence = Persistence(root / "metrics.sqlite3", root / "audit.jsonl")
        self.addCleanup(persistence.close)
        persistence.runs.create(self.run_id, "demo", state="RUNNING")
        with LocalDemoServer(TelemetryScenario.NORMAL_LATENCY) as server:
            probe = LocalTelemetryProbe(
                port=server.port,
                run_id=self.run_id,
                limits=self.enforcer,
                kill_switch=self.kill_switch,
                persistence=persistence,
            )
            probe.sample()

        metrics = persistence.metrics.list_for_run(self.run_id)
        self.assertEqual(
            {metric.name for metric in metrics},
            {"cpu_percent", "ram_percent", "rtt_ms", "drop_rate"},
        )
        events = persistence.events.list_for_run(self.run_id)
        sample_events = [event for event in events if event.name == "metric.sample"]
        self.assertEqual(len(sample_events), 1)
        self.assertEqual(sample_events[0].payload["status_code"], 200)

        audit_entries = [
            json.loads(line)
            for line in (root / "audit.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        self.assertEqual(len(audit_entries), 1)
        audit_payload = audit_entries[0]["payload"]
        self.assertIn("cpu_percent", audit_payload)
        self.assertIn("ram_percent", audit_payload)
        self.assertIn("drop_rate", audit_payload)


if __name__ == "__main__":
    unittest.main()
