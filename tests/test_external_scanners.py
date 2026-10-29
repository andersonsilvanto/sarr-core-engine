import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from core.security_audit import SecurityFinding
from core.state_machine import RunState
from sarr_core import cli
from sarr_core.external_scanners import ExternalScannerManager
from sarr_core.scanner_bootstrap import ScannerBootstrap, ScannerInstallation
from sarr_core.simulation import SecurityScenario, SimulationSnapshot


class ExternalScannerTests(unittest.TestCase):
    def test_missing_tools_report_informational_findings_and_keep_fallback(self) -> None:
        with patch("sarr_core.scanner_bootstrap.shutil.which", return_value=None):
            result = ExternalScannerManager(Path.cwd()).run_local_checks()

        self.assertEqual(len(result.statuses), 2)
        self.assertTrue(
            all("fallback interno ativo" in status for _, status in result.statuses)
        )
        self.assertEqual(
            {finding.event_name for finding in result.findings},
            {"external.scanner.unavailable"},
        )
        self.assertTrue(all(finding.severity == "info" for finding in result.findings))

    def test_scanner_bootstrap_reports_manual_guidance_without_installing(self) -> None:
        with patch("sarr_core.scanner_bootstrap.shutil.which", return_value=None):
            installations = ScannerBootstrap().inspect()

        self.assertEqual(
            {installation.name for installation in installations},
            {"nmap", "tshark"},
        )
        self.assertTrue(all(not installation.available for installation in installations))
        guidance = ScannerBootstrap.installation_guidance(installations)
        self.assertTrue(any("winget install --id Insecure.Nmap" in line for line in guidance))
        self.assertTrue(
            any("winget install --id WiresharkFoundation.Wireshark" in line for line in guidance)
        )
        self.assertTrue(any("não baixa nem executa instaladores" in line for line in guidance))

    def test_scanner_bootstrap_checks_standard_windows_install_paths(self) -> None:
        with (
            patch("sarr_core.scanner_bootstrap.sys.platform", "win32"),
            patch.dict(
                os.environ,
                {
                    "ProgramFiles": "C:/Programs",
                    "ProgramFiles(x86)": "C:/Programs x86",
                },
                clear=False,
            ),
            patch("sarr_core.scanner_bootstrap.shutil.which", return_value=None),
            patch.object(Path, "is_file", autospec=True, side_effect=lambda path: path.name == "tshark.exe"),
        ):
            nmap = ScannerBootstrap().locate("nmap")
            tshark = ScannerBootstrap().locate("tshark")

        self.assertIsNone(nmap.executable)
        self.assertEqual(tshark.executable, Path("C:/Programs/Wireshark/tshark.exe"))

    def test_cli_bootstrap_scanners_reports_availability_and_guidance(self) -> None:
        installations = (
            ScannerInstallation("nmap", None, "Insecure.Nmap"),
            ScannerInstallation("tshark", Path("tshark.exe"), "WiresharkFoundation.Wireshark"),
        )
        output = io.StringIO()
        with (
            patch.object(ScannerBootstrap, "inspect", return_value=installations),
            redirect_stdout(output),
        ):
            status = cli.main(["--bootstrap-scanners"])

        self.assertEqual(status, 0)
        self.assertIn("nmap: não encontrado", output.getvalue())
        self.assertIn("tshark: tshark.exe", output.getvalue())
        self.assertIn("Instalação assistida", output.getvalue())

    def test_cli_prints_clear_warning_when_external_tools_are_unavailable(self) -> None:
        unavailable = SecurityFinding(
            event_name="external.scanner.unavailable",
            severity="info",
            summary="Nmap/Tshark unavailable; internal fallback remains active.",
            evidence={"fallback": "internal_simulation"},
            vetor_ataque="N/A",
            remediacao="Install the optional local tool.",
            mitre_id="",
            acao_bloqueio="Continue with internal fixtures.",
        )
        snapshot = SimulationSnapshot(
            uuid4(),
            RunState.COMPLETED,
            (unavailable,),
            scanner_status=(
                ("Nmap", "indisponível — fallback interno ativo"),
                ("Tshark", "indisponível — fallback interno ativo"),
            ),
        )

        class FakeSession:
            data_directory = Path(".")
            last_scenario: SecurityScenario | None = None
            last_capture: Path | None = None

            def __init__(
                self,
                scenario: SecurityScenario,
                *,
                tshark_capture: Path | None = None,
            ) -> None:
                type(self).last_scenario = scenario
                type(self).last_capture = tshark_capture

            def run(self) -> SimulationSnapshot:
                return snapshot

            def event_log(self) -> tuple[tuple[str, str], ...]:
                return ()

            def close(self) -> None:
                return None

        output = io.StringIO()
        with patch("sarr_core.cli.LocalSimulationSession", FakeSession):
            with redirect_stdout(output):
                status = cli._run_simulation(SecurityScenario.NORMAL)

        self.assertEqual(status, 0)
        self.assertEqual(FakeSession.last_scenario, SecurityScenario.NORMAL)
        self.assertIsNone(FakeSession.last_capture)
        self.assertIn("Aviso:", output.getvalue())
        self.assertIn("fallback interno ativo", output.getvalue())

    def test_nmap_invocation_is_fixed_to_loopback_and_parses_xml(self) -> None:
        nmap_xml = (
            '<nmaprun><host><ports><port protocol="tcp" portid="8080">'
            '<state state="open"/><service name="http-alt"/></port></ports></host></nmaprun>'
        )
        version_result = type("Result", (), {"returncode": 0, "stdout": "TShark 4"})()
        scan_result = type(
            "Result",
            (),
            {"returncode": 0, "stdout": nmap_xml},
        )()
        with (
            patch(
                "sarr_core.scanner_bootstrap.shutil.which",
                side_effect=lambda name: f"C:/tools/{name}.exe",
            ),
            patch(
                "sarr_core.external_scanners.subprocess.run",
                side_effect=[scan_result, version_result],
            ) as run,
        ):
            result = ExternalScannerManager(Path.cwd()).run_local_checks()

        invocation = run.call_args_list[0]
        self.assertEqual(invocation.args[0][-1], "127.0.0.1")
        self.assertIs(invocation.kwargs["shell"], False)
        finding = next(
            finding
            for finding in result.findings
            if finding.event_name == "network.nmap.port_discovered"
        )
        self.assertEqual(finding.evidence["port"], 8080)
        self.assertEqual(finding.severity, "info")

    def test_tshark_offline_analysis_is_project_scoped_and_payload_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "authorized.pcapng"
            capture.write_bytes(b"synthetic capture")
            completed = type(
                "Result",
                (),
                {"returncode": 0, "stdout": "1\teth:ip:tcp\n2\teth:ip:udp\n"},
            )()
            with (
                patch("sarr_core.scanner_bootstrap.shutil.which", return_value="tshark"),
                patch(
                    "sarr_core.external_scanners.subprocess.run",
                    return_value=completed,
                ) as run,
            ):
                finding = ExternalScannerManager(root).analyze_capture(capture)

            arguments = run.call_args.args[0]
            self.assertEqual(finding.event_name, "network.tshark.capture_analyzed")
            self.assertEqual(finding.evidence["frame_count"], 2)
            self.assertEqual(
                len(finding.evidence["analysis_signature_sha256"]),
                64,
            )
            self.assertIn("-r", arguments)
            self.assertNotIn("-i", arguments)
            self.assertNotIn("-w", arguments)

    def test_run_checks_integrates_authorized_offline_tshark_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "authorized.pcap"
            capture.write_bytes(b"synthetic capture")
            version_result = type("Result", (), {"returncode": 0, "stdout": "TShark"})()
            capture_result = type(
                "Result",
                (),
                {"returncode": 0, "stdout": "1\teth:ip:tcp\n"},
            )()
            with (
                patch(
                    "sarr_core.scanner_bootstrap.shutil.which",
                    side_effect=lambda name: "tshark.exe" if name == "tshark" else None,
                ),
                patch(
                    "sarr_core.external_scanners.subprocess.run",
                    side_effect=[version_result, capture_result],
                ),
            ):
                result = ExternalScannerManager(root).run_local_checks(
                    offline_capture=capture
                )

        self.assertIn(
            "network.tshark.capture_analyzed",
            {finding.event_name for finding in result.findings},
        )

    def test_tshark_refuses_capture_outside_project_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            outside_capture = Path(directory) / "outside.pcap"
            outside_capture.write_bytes(b"fixture")
            with patch("sarr_core.scanner_bootstrap.shutil.which", return_value="tshark"):
                with self.assertRaisesRegex(ValueError, "inside the project"):
                    ExternalScannerManager(root).analyze_capture(outside_capture)

    def test_plaintext_capture_on_nmap_port_is_correlated_as_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "authorized.pcap"
            capture.write_bytes(b"synthetic authorized capture")
            nmap_result = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": (
                        '<nmaprun><host><ports><port protocol="tcp" portid="8080">'
                        '<state state="open"/><service name="http-alt"/></port>'
                        "</ports></host></nmaprun>"
                    ),
                },
            )()
            version_result = type(
                "Result",
                (),
                {"returncode": 0, "stdout": "TShark"},
            )()
            capture_result = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": (
                        "1\teth:ip:tcp:http\t49152\t8080\t\t\t"
                        "127.0.0.1\t127.0.0.1\t\t\n"
                    ),
                },
            )()
            with (
                patch(
                    "sarr_core.scanner_bootstrap.shutil.which",
                    side_effect=lambda name: f"C:/tools/{name}.exe",
                ),
                patch(
                    "sarr_core.external_scanners.subprocess.run",
                    side_effect=[nmap_result, version_result, capture_result],
                ),
            ):
                result = ExternalScannerManager(root).run_local_checks(capture)

        finding = next(
            item
            for item in result.findings
            if item.event_name == "network.correlation.vulnerability_detected"
        )
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.mitre_id, "T1040")
        self.assertEqual(finding.evidence["port"], 8080)
        self.assertEqual(finding.evidence["protocols"], ["http"])
        self.assertEqual(
            finding.evidence["source"],
            "nmap_tshark_offline_correlation",
        )

    def test_tls_capture_does_not_report_plaintext_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "authorized.pcap"
            capture.write_bytes(b"synthetic authorized capture")
            nmap_result = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": (
                        '<nmaprun><host><ports><port protocol="tcp" portid="443">'
                        '<state state="open"/><service name="https"/></port>'
                        "</ports></host></nmaprun>"
                    ),
                },
            )()
            version_result = type(
                "Result",
                (),
                {"returncode": 0, "stdout": "TShark"},
            )()
            capture_result = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": (
                        "1\teth:ip:tcp:tls:http\t49152\t443\t\t\t"
                        "127.0.0.1\t127.0.0.1\t\t\n"
                    ),
                },
            )()
            with (
                patch(
                    "sarr_core.scanner_bootstrap.shutil.which",
                    side_effect=lambda name: f"/tools/{name}",
                ),
                patch(
                    "sarr_core.external_scanners.subprocess.run",
                    side_effect=[nmap_result, version_result, capture_result],
                ),
            ):
                result = ExternalScannerManager(root).run_local_checks(capture)

        self.assertNotIn(
            "network.correlation.vulnerability_detected",
            {item.event_name for item in result.findings},
        )

    def test_correlation_ignores_plaintext_capture_outside_loopback(self) -> None:
        findings = ExternalScannerManager._correlate_plaintext_traffic(
            [
                [
                    "1",
                    "eth:ip:tcp:http",
                    "49152",
                    "8080",
                    "",
                    "",
                    "192.0.2.10",
                    "198.51.100.20",
                    "",
                    "",
                ]
            ],
            capture_name="authorized.pcap",
            discovered_ports={8080: "http-alt"},
        )

        self.assertEqual(findings, ())


if __name__ == "__main__":
    unittest.main()
