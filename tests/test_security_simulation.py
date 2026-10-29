import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from core.security_audit import PortEvidence, SecurityAudit
from core.events import EventBus
from core.kill_switch import KillSwitch
from sarr_core.simulation import LocalSimulationSession, SecurityScenario


class SecuritySimulationTests(unittest.TestCase):
    def run_scenario(self, scenario: SecurityScenario):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        data_directory = Path(temporary_directory.name) / "data"
        data_directory.mkdir()
        with patch(
            "sarr_core.simulation.resolve_data_directory",
            return_value=data_directory,
        ):
            session = LocalSimulationSession(scenario)
            snapshot = session.run()
            events = session.event_log()
        audit_entries = [
            json.loads(line)
            for line in (data_directory / "audit.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        return snapshot, events, audit_entries

    def test_normal_audit_uses_local_evidence_and_completes(self) -> None:
        snapshot, events, entries = self.run_scenario(SecurityScenario.NORMAL)

        self.assertEqual(snapshot.state.value, "COMPLETED")
        self.assertFalse(
            any(finding.severity in {"critical", "high"} for finding in snapshot.findings)
        )
        names = {name for _, name in events}
        self.assertIn("security.audit.started", names)
        self.assertIn("security.audit.completed", names)
        self.assertIn("security.port.reviewed", names)
        self.assertIn("integrity.hash.verified", names)
        self.assertTrue(
            {
                "security.permission.verified",
                "security.permission.audit_unavailable",
            }.intersection(names)
        )
        self.assertNotIn("metric.sample", names)
        self.assertTrue(
            all(entry["event_type"] != "event.other" for entry in entries)
        )

    def test_unauthorized_loopback_inventory_trips_kill_switch(self) -> None:
        snapshot, events, entries = self.run_scenario(
            SecurityScenario.UNAUTHORIZED_PORT
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn(
            "security.port.exposed",
            [finding.event_name for finding in snapshot.findings],
        )
        self.assertIn("safety.triggered", {name for _, name in events})
        safety_entry = next(
            entry
            for entry in entries
            if entry["event_type"] == "safety.triggered"
        )
        self.assertEqual(
            safety_entry["payload"]["reason_code"],
            "unauthorized_local_service",
        )

    def test_integrity_mismatch_trips_kill_switch_and_is_persisted(self) -> None:
        snapshot, events, entries = self.run_scenario(
            SecurityScenario.INTEGRITY_MISMATCH
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn(
            "integrity.hash.mismatch",
            [finding.event_name for finding in snapshot.findings],
        )
        self.assertIn("finding.created", {name for _, name in events})
        self.assertTrue(
            any(
                entry["event_type"] == "integrity.hash.mismatch"
                for entry in entries
            )
        )

    def test_synthetic_brute_force_scenario_is_detected_and_blocked(self) -> None:
        snapshot, events, _ = self.run_scenario(SecurityScenario.BRUTE_FORCE)

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn(
            "auth.brute_force.detected",
            [finding.event_name for finding in snapshot.findings],
        )
        self.assertIn("safety.triggered", {name for _, name in events})

    def test_manual_interruption_is_fail_closed(self) -> None:
        snapshot, events, _ = self.run_scenario(
            SecurityScenario.MANUAL_INTERRUPTION
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn("safety.triggered", {name for _, name in events})

    def test_port_evidence_rejects_non_loopback_hosts(self) -> None:
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            PortEvidence(
                host="192.0.2.1",
                port=443,
                service="fixture",
                authorized=False,
            )

    def test_audit_rejects_paths_outside_the_project_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            outside_path = Path(directory) / "outside.json"
            outside_path.write_text("{}", encoding="utf-8")
            audit = SecurityAudit(
                run_id=uuid4(),
                event_bus=EventBus(),
                kill_switch=KillSwitch(),
                project_root=root,
            )

            with self.assertRaisesRegex(ValueError, "inside the project root"):
                audit.run(
                    ports=(),
                    integrity=(),
                    permission_paths=(outside_path,),
                )


if __name__ == "__main__":
    unittest.main()
