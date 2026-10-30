import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from core import Persistence
from core.security_audit import (
    IntegrityEvidence,
    PortEvidence,
    SecurityAudit,
    SecurityFinding,
)
from core.events import EventBus
from core.kill_switch import KillSwitch
from sarr_core.metadata import MetadataManager
from sarr_core.simulation import (
    LocalSimulationSession,
    SecurityScenario,
    hardening_score,
    restore_known_baselines,
)
from sarr_core.external_scanners import ExternalScannerResult


class SecuritySimulationTests(unittest.TestCase):
    def run_scenario(self, scenario: SecurityScenario):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        data_directory = Path(temporary_directory.name) / "data"
        data_directory.mkdir()
        with (
            patch(
                "sarr_core.simulation.resolve_data_directory",
                return_value=data_directory,
            ),
            patch(
                "sarr_core.simulation.ExternalScannerManager.run_local_checks",
                return_value=ExternalScannerResult((), ()),
            ),
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
        return snapshot, events, audit_entries, data_directory

    def test_normal_audit_uses_local_evidence_and_completes(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(SecurityScenario.NORMAL)

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
        atomic_events = [
            entry
            for entry in entries
            if entry["event_type"] == "atomic.tactic.completed"
        ]
        self.assertEqual(
            {entry["payload"]["mitre_id"] for entry in atomic_events},
            {"T1083", "T1046", "T1222"},
        )
        verified_paths = {
            entry["payload"]["path"]
            for entry in entries
            if entry["event_type"] == "integrity.hash.verified"
        }
        self.assertEqual(
            verified_paths,
            {
                "config/dashboard.schema.json",
                "config/canary_credentials.json",
                "config/network_detection.json",
                "schemas/dashboard.schema.json",
                "schemas/network_detection.schema.json",
                "schemas/scope.schema.json",
            },
        )
        self.assertGreater(snapshot.hardening_score, 0)

    def test_scanner_fallback_is_reported_in_run_events_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory) / "data"
            data_directory.mkdir()
            with (
                patch(
                    "sarr_core.simulation.resolve_data_directory",
                    return_value=data_directory,
                ),
                patch(
                    "sarr_core.scanner_bootstrap.shutil.which",
                    return_value=None,
                ),
            ):
                session = LocalSimulationSession()
                snapshot = session.run()
                events = session.event_log()

            self.assertEqual(snapshot.state.value, "COMPLETED")
            self.assertTrue(
                {
                    finding.event_name
                    for finding in snapshot.findings
                }.issuperset({"external.scanner.unavailable"})
            )
            self.assertEqual(
                {tool for tool, _ in snapshot.scanner_status},
                {"Nmap", "Tshark"},
            )
            self.assertIn("external.scanner.status", {name for _, name in events})
            audit_records = [
                json.loads(line)
                for line in (data_directory / "audit.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertTrue(
                all(
                    record["event_type"] != "event.other"
                    for record in audit_records
                )
            )

    def test_critical_network_correlation_trips_kill_switch_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory) / "data"
            data_directory.mkdir()
            correlation = SecurityFinding(
                event_name="network.correlation.vulnerability_detected",
                severity="critical",
                summary="Plaintext HTTP observed on loopback port 8080.",
                evidence={
                    "host": "127.0.0.1",
                    "port": 8080,
                    "service": "http-alt",
                    "protocols": ["http"],
                    "frame_count": 1,
                    "capture_name": "authorized.pcap",
                    "source": "nmap_tshark_offline_correlation",
                },
                vetor_ataque="Observed cleartext application traffic.",
                remediacao="Enable TLS and repeat the authorized offline audit.",
                mitre_id="T1040",
                acao_bloqueio="Keep the run blocked pending review.",
            )
            result = ExternalScannerResult(
                (("Nmap", "disponível"), ("Tshark", "análise offline concluída")),
                (correlation,),
            )
            with (
                patch(
                    "sarr_core.simulation.resolve_data_directory",
                    return_value=data_directory,
                ),
                patch(
                    "sarr_core.simulation.ExternalScannerManager.run_local_checks",
                    return_value=result,
                ),
            ):
                session = LocalSimulationSession()
                snapshot = session.run()
                events = session.event_log()

            self.assertEqual(snapshot.state.value, "BLOCKED")
            self.assertIn(
                "network.correlation.vulnerability_detected",
                {name for _, name in events},
            )
            self.assertIn("safety.triggered", {name for _, name in events})
            audit_records = [
                json.loads(line)
                for line in (data_directory / "audit.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            correlated_events = [
                record
                for record in audit_records
                if record["event_type"]
                == "network.correlation.vulnerability_detected"
            ]
            self.assertEqual(len(correlated_events), 1)
            self.assertEqual(correlated_events[0]["payload"]["mitre_id"], "T1040")
            persistence = Persistence(
                data_directory / "sarr-core.sqlite3",
                data_directory / "audit.jsonl",
            )
            try:
                critical_events = persistence.events.list_critical()
            finally:
                persistence.close()
            self.assertIn(
                "network.correlation.vulnerability_detected",
                {event.name for event in critical_events},
            )

    def test_unauthorized_loopback_inventory_trips_kill_switch(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(
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
        snapshot, events, entries, _ = self.run_scenario(
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
        snapshot, events, _, _ = self.run_scenario(SecurityScenario.BRUTE_FORCE)

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn(
            "auth.brute_force.detected",
            [finding.event_name for finding in snapshot.findings],
        )
        self.assertIn("safety.triggered", {name for _, name in events})

    def test_manual_interruption_is_fail_closed(self) -> None:
        snapshot, events, _, _ = self.run_scenario(
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

    def test_file_without_approved_baseline_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extra_file = root / "config" / "new-settings.json"
            extra_file.parent.mkdir()
            extra_file.write_text("{}", encoding="utf-8")
            kill_switch = KillSwitch()
            audit = SecurityAudit(
                run_id=uuid4(),
                event_bus=EventBus(),
                kill_switch=kill_switch,
                project_root=root,
            )

            findings = audit.run(
                ports=(),
                integrity=(
                    IntegrityEvidence(extra_file, None),
                ),
                permission_paths=(),
            )

            self.assertEqual(findings[0].event_name, "integrity.baseline.missing")
            self.assertTrue(kill_switch.is_triggered)
            self.assertEqual(
                kill_switch.event.reason_code,
                "integrity_baseline_missing",
            )

    def test_verified_baseline_restoration_is_limited_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = (
                Path(__file__).resolve().parents[1]
                / "schemas"
                / "dashboard.schema.json"
            )
            source_target = root / "schemas" / "dashboard.schema.json"
            repair_target = root / "config" / "dashboard.schema.json"
            source_target.parent.mkdir()
            repair_target.parent.mkdir()
            source_target.write_bytes(source.read_bytes())
            repair_target.write_text('{"tampered": true}', encoding="utf-8")
            untouched = root / "config" / "operator-settings.json"
            untouched.write_text('{"keep": true}', encoding="utf-8")

            restored = restore_known_baselines(root)

            self.assertEqual(restored, (repair_target.resolve(),))
            self.assertEqual(
                repair_target.read_bytes(),
                (
                    json.dumps(
                        json.loads(source.read_text(encoding="utf-8")),
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            self.assertEqual(
                untouched.read_text(encoding="utf-8"),
                '{"keep": true}',
            )

    def test_baseline_restoration_refuses_untrusted_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "schemas" / "dashboard.schema.json"
            source.parent.mkdir()
            source.write_text('{"tampered": true}', encoding="utf-8")
            target = root / "config" / "dashboard.schema.json"
            target.parent.mkdir()
            target.write_text('{"target": "unchanged"}', encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "failed verification"):
                restore_known_baselines(root)
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                '{"target": "unchanged"}',
            )

    def test_hardening_score_decreases_with_finding_severity(self) -> None:
        snapshot, _, _, _ = self.run_scenario(
            SecurityScenario.PORTA_DESPROTEGIDA
        )

        self.assertEqual(hardening_score(()), 100)
        self.assertLess(snapshot.hardening_score, 100)

    def test_synthetic_obfuscation_indicators_are_detected_without_execution(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(SecurityScenario.OBFUSCATION)
        finding = next(
            item
            for item in snapshot.findings
            if item.event_name == "evasion.obfuscation.detected"
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.mitre_id, "T1027")
        self.assertEqual(finding.evidence["base64_sample_count"], 1)
        self.assertEqual(finding.evidence["suspicious_command_count"], 1)
        self.assertIn("safety.triggered", {name for _, name in events})
        serialized_events = json.dumps(entries, ensure_ascii=False)
        self.assertNotIn("EncodedCommand", serialized_events)
        self.assertNotIn("SYNTHETIC_ONLY", serialized_events)

    def test_synthetic_persistence_indicators_are_detected_and_blocked(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(SecurityScenario.PERSISTENCE)
        findings = [
            item
            for item in snapshot.findings
            if item.event_name == "persistence.point.detected"
        ]

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {finding.mitre_id for finding in findings},
            {"T1053.005", "T1547.001"},
        )
        self.assertIn("safety.triggered", {name for _, name in events})
        self.assertTrue(
            any(entry["event_type"] == "persistence.point.detected" for entry in entries)
        )
        self.assertNotIn("schtasks.exe", json.dumps(entries))

    def test_canary_access_triggers_critical_finding_and_kill_switch(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(SecurityScenario.CANARY_ACCESS)
        canary = next(
            finding
            for finding in snapshot.findings
            if finding.event_name == "deception.canary.triggered"
        )
        audit_event = next(
            entry
            for entry in entries
            if entry["event_type"] == "deception.canary.triggered"
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertEqual(canary.severity, "critical")
        self.assertEqual(canary.evidence["reason"], "accessed")
        self.assertEqual(canary.summary, "O arquivo-isca canário foi acessado.")
        self.assertEqual(audit_event["payload"]["severity"], "critical")
        self.assertIn("safety.triggered", {name for _, name in events})

    def test_modified_canary_triggers_deception_event_and_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = root / "config" / "canary_credentials.json"
            canary.parent.mkdir()
            canary.write_text('{"tampered": true}', encoding="utf-8")
            bus = EventBus()
            kill_switch = KillSwitch()
            audit = SecurityAudit(
                run_id=uuid4(),
                event_bus=bus,
                kill_switch=kill_switch,
                project_root=root,
            )

            findings = audit.run(
                ports=(),
                integrity=(IntegrityEvidence(canary, "0" * 64),),
                permission_paths=(),
            )

        self.assertEqual(findings[0].event_name, "deception.canary.triggered")
        self.assertEqual(findings[0].evidence["reason"], "modified")
        self.assertTrue(kill_switch.is_triggered)
        self.assertEqual(kill_switch.event.reason_code, "canary_triggered")
        self.assertIn(
            "deception.canary.triggered",
            [event.name for event in bus.history],
        )

    def test_changed_approved_file_is_atomically_healed_from_memory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            data_directory = Path(directory) / "data"
            data_directory.mkdir()
            for relative_path in (
                "config/dashboard.schema.json",
                "config/canary_credentials.json",
                "config/network_detection.json",
                "schemas/dashboard.schema.json",
                "schemas/network_detection.schema.json",
                "schemas/scope.schema.json",
            ):
                source = Path(__file__).resolve().parents[1] / relative_path
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            target = root / "config" / "dashboard.schema.json"
            approved_content = target.read_bytes()

            with (
                patch("sarr_core.simulation._resolve_project_root", return_value=root),
                patch("sarr_core.simulation.resolve_data_directory", return_value=data_directory),
                patch(
                    "sarr_core.simulation.ExternalScannerManager.run_local_checks",
                    return_value=ExternalScannerResult((), ()),
                ),
            ):
                session = LocalSimulationSession()
                target.write_text('{"tampered": true}', encoding="utf-8")
                snapshot = session.run()
                events = session.event_log()

            self.assertEqual(target.read_bytes(), approved_content)
            self.assertEqual(snapshot.state.value, "COMPLETED")
            self.assertEqual(snapshot.healed_paths, ("config/dashboard.schema.json",))
            self.assertIn("security.state.healed", {name for _, name in events})
            healed_log = next(
                entry
                for entry in (
                    json.loads(line)
                    for line in (data_directory / "audit.jsonl").read_text(
                        encoding="utf-8"
                    ).splitlines()
                )
                if entry["event_type"] == "security.state.healed"
            )
            self.assertEqual(
                healed_log["payload"]["status"],
                "RESTORED / HEALED",
            )

    def test_preexisting_tampering_without_trusted_shadow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            data_directory = Path(directory) / "data"
            data_directory.mkdir()
            for relative_path in (
                "config/dashboard.schema.json",
                "config/canary_credentials.json",
                "config/network_detection.json",
                "schemas/dashboard.schema.json",
                "schemas/network_detection.schema.json",
                "schemas/scope.schema.json",
            ):
                source = Path(__file__).resolve().parents[1] / relative_path
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            target = root / "config" / "dashboard.schema.json"
            target.write_text('{"tampered": true}', encoding="utf-8")

            with (
                patch("sarr_core.simulation._resolve_project_root", return_value=root),
                patch("sarr_core.simulation.resolve_data_directory", return_value=data_directory),
                patch(
                    "sarr_core.simulation.ExternalScannerManager.run_local_checks",
                    return_value=ExternalScannerResult((), ()),
                ),
            ):
                session = LocalSimulationSession()
                snapshot = session.run()

            self.assertEqual(snapshot.state.value, "BLOCKED")
            self.assertFalse(snapshot.healed_paths)
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                '{"tampered": true}',
            )

    def test_synthetic_ghost_port_engagement_records_only_signature_hash(self) -> None:
        snapshot, events, entries, _ = self.run_scenario(SecurityScenario.GHOST_PORT)
        finding = next(
            item
            for item in snapshot.findings
            if item.event_name == "deception.ghost_port.engaged"
        )
        event = next(
            entry
            for entry in entries
            if entry["event_type"] == "deception.ghost_port.engaged"
        )

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.evidence["host"], "127.0.0.1")
        self.assertEqual(len(finding.evidence["request_signature_sha256"]), 64)
        self.assertNotIn("HTTP/1.1|SARR_SYNTHETIC", json.dumps(event))
        self.assertEqual(event["payload"]["source"], "synthetic_local_fixture")
        self.assertIn("safety.triggered", {name for _, name in events})

    def test_session_exports_sanitized_executive_reports_as_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_directory = Path(directory) / "data"
            data_directory.mkdir()
            with patch(
                "sarr_core.simulation.resolve_data_directory",
                return_value=data_directory,
            ):
                session = LocalSimulationSession(SecurityScenario.OBFUSCATION)
                snapshot = session.run()
                json_path = session.export_executive_report(
                    data_directory / "exports" / "executive.json",
                    format="json",
                )
                markdown_path = session.export_executive_report(
                    data_directory / "exports" / "executive.md",
                    format="markdown",
                )
            json_report = json.loads(json_path.read_text(encoding="utf-8"))
            markdown_report = markdown_path.read_text(encoding="utf-8")

        self.assertEqual(snapshot.state.value, "BLOCKED")
        self.assertIn("evasion.obfuscation.detected", json.dumps(json_report))
        self.assertIn("Relatório Executivo de Auditoria", markdown_report)
        self.assertIn("evasion.obfuscation.detected", markdown_report)
        self.assertNotIn("EncodedCommand", markdown_report)

    def test_requested_rich_scenarios_export_actionable_findings(self) -> None:
        scenarios = (
            (
                SecurityScenario.PORTA_DESPROTEGIDA,
                "security.port.exposed",
                "T1046",
                {"port": 8080, "authentication": "absent"},
                (
                    "New-NetFirewallRule",
                    "sudo ufw deny 8080/tcp",
                ),
            ),
            (
                SecurityScenario.PERMISSAO_FROUXA,
                "security.permission.excessive",
                "T1222",
                {"path": "config/runtime.json", "world_writable": True},
                (
                    "chmod go-w config/runtime.json",
                    "icacls.exe",
                ),
            ),
            (
                SecurityScenario.HASH_ADULTERADO,
                "integrity.hash.mismatch",
                "T1565.001",
                {
                    "path": "schemas/scope.schema.json",
                    "expected_sha256": "0" * 64,
                },
                (
                    "Get-FileHash",
                    "sha256sum schemas/scope.schema.json",
                ),
            ),
        )
        required_fields = {
            "vetor_ataque",
            "remediacao",
            "mitre_id",
            "acao_bloqueio",
        }

        for scenario, event_name, mitre_id, expected_evidence, commands in scenarios:
            with self.subTest(scenario=scenario.value):
                snapshot, _, audit_entries, data_directory = self.run_scenario(
                    scenario
                )
                self.assertEqual(snapshot.state.value, "BLOCKED")
                finding = next(
                    entry
                    for entry in snapshot.findings
                    if entry.event_name == event_name
                )
                self.assertEqual(finding.mitre_id, mitre_id)
                self.assertTrue(finding.vetor_ataque)
                self.assertTrue(finding.remediacao)
                self.assertTrue(finding.acao_bloqueio)
                for command in commands:
                    self.assertIn(command, finding.remediacao)
                for evidence_key, expected_value in expected_evidence.items():
                    self.assertEqual(
                        finding.evidence[evidence_key],
                        expected_value,
                    )

                finding_event = next(
                    entry
                    for entry in audit_entries
                    if entry["event_type"] == event_name
                )
                self.assertTrue(
                    required_fields.issubset(finding_event["payload"])
                )
                metadata_path = MetadataManager(
                    data_directory / "sarr-core.sqlite3"
                ).export_latest_run(data_directory / "metadata.json")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                exported_finding = next(
                    row
                    for row in metadata["findings"]
                    if row["title"] == event_name
                )
                self.assertTrue(
                    required_fields.issubset(exported_finding["details"])
                )
                self.assertEqual(
                    exported_finding["details"]["mitre_id"],
                    mitre_id,
                )


if __name__ == "__main__":
    unittest.main()
