import importlib.util
import unittest
from unittest.mock import patch
from uuid import uuid4

from core.security_audit import SecurityFinding

_HAS_TKINTER = importlib.util.find_spec("tkinter") is not None
if _HAS_TKINTER:
    import tkinter as tk

    from sarr_core.gui import LocalDashboard, launch_gui


class FakeRoot:
    def __init__(self) -> None:
        self.mainloop_called = False

    def mainloop(self) -> None:
        self.mainloop_called = True


@unittest.skipUnless(_HAS_TKINTER, "Tkinter is not installed")
class GuiTests(unittest.TestCase):
    def test_soc_event_severity_classification(self) -> None:
        self.assertEqual(
            LocalDashboard._severity_for_event("security.port.exposed"),
            "CRITICAL",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event(
                "security.permission.audit_unavailable"
            ),
            "WARNING",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event("security.audit.completed"),
            "INFO",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event("deception.canary.triggered"),
            "CRITICAL",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event("evasion.obfuscation.detected"),
            "CRITICAL",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event("deception.ghost_port.engaged"),
            "CRITICAL",
        )
        self.assertEqual(
            LocalDashboard._severity_for_event(
                "network.correlation.vulnerability_detected"
            ),
            "CRITICAL",
        )

    def test_soc_posture_fails_closed_for_findings_and_kill_switch(self) -> None:
        self.assertEqual(
            LocalDashboard._posture_for("COMPLETED", 0, False),
            ("SEGURO", "Posture.SECURE.TLabel"),
        )
        self.assertEqual(
            LocalDashboard._posture_for("COMPLETED", 1, False),
            ("VULNERÁVEL", "Posture.VULNERABLE.TLabel"),
        )
        self.assertEqual(
            LocalDashboard._posture_for("BLOCKED", 0, True),
            ("ATAQUE / KILL-SWITCH", "Posture.ATTACK.TLabel"),
        )

    def test_traffic_light_colors_match_security_posture(self) -> None:
        self.assertEqual(
            LocalDashboard._traffic_color_for("Posture.SECURE.TLabel"),
            "#16803c",
        )
        self.assertEqual(
            LocalDashboard._traffic_color_for("Posture.VULNERABLE.TLabel"),
            "#eab308",
        )
        self.assertEqual(
            LocalDashboard._traffic_color_for("Posture.ATTACK.TLabel"),
            "#b42318",
        )
        self.assertEqual(
            LocalDashboard._traffic_color_for("Posture.PENDING.TLabel"),
            "#667085",
        )

    def test_dynamic_integrity_indicator_reports_healed_and_fail_closed_states(self) -> None:
        from core.state_machine import RunState
        from sarr_core.simulation import SimulationSnapshot

        run_id = uuid4()
        self.assertEqual(
            LocalDashboard._integrity_status_for(
                SimulationSnapshot(run_id, RunState.COMPLETED, (), ("config/test.json",))
            ),
            "RESTAURADO / CORRIGIDO",
        )
        self.assertEqual(
            LocalDashboard._integrity_status_for(
                SimulationSnapshot(run_id, RunState.BLOCKED, ())
            ),
            "NÃO VERIFICADO / FAIL-CLOSED",
        )

    def test_scanner_pipeline_indicator_distinguishes_ready_and_fallback(self) -> None:
        from core.state_machine import RunState
        from sarr_core.simulation import SimulationSnapshot

        run_id = uuid4()
        ready = SimulationSnapshot(
            run_id,
            RunState.COMPLETED,
            (),
            scanner_status=(
                ("Nmap", "disponível — verificação limitada a 127.0.0.1"),
                ("Tshark", "análise offline concluída; captura ao vivo desativada"),
            ),
        )
        fallback = SimulationSnapshot(
            run_id,
            RunState.COMPLETED,
            (),
            scanner_status=(
                ("Nmap", "indisponível — fallback interno ativo"),
                ("Tshark", "indisponível — fallback interno ativo"),
            ),
        )

        self.assertEqual(
            LocalDashboard._scanner_pipeline_status_for(ready),
            "PRONTO — Nmap em 127.0.0.1 + Tshark offline",
        )
        self.assertEqual(
            LocalDashboard._scanner_pipeline_status_for(fallback),
            "ALTERNATIVO — simulação interna ativa",
        )

    def test_findings_table_severity_tags_are_normalized(self) -> None:
        for severity, expected in (
            ("critical", "CRITICAL"),
            ("high", "CRITICAL"),
            ("medium", "WARNING"),
            ("warning", "WARNING"),
            ("low", "INFO"),
            ("info", "INFO"),
            ("unexpected", "INFO"),
        ):
            with self.subTest(severity=severity):
                self.assertEqual(
                    LocalDashboard._row_tag_for_severity(severity),
                    expected,
                )

    def test_findings_display_severity_is_in_portuguese(self) -> None:
        for severity, expected in (
            ("CRITICAL", "CRÍTICO"),
            ("WARNING", "ATENÇÃO"),
            ("INFO", "INFORMATIVO"),
        ):
            with self.subTest(severity=severity):
                self.assertEqual(LocalDashboard._severity_label(severity), expected)

    def test_selected_finding_details_include_red_blue_and_blocking_guidance(self) -> None:
        finding = SecurityFinding(
            event_name="security.port.exposed",
            severity="critical",
            summary="Synthetic unauthenticated service.",
            evidence={"port": 8080, "source": "synthetic_local_inventory"},
            vetor_ataque="High-level attack path.",
            remediacao="sudo ufw deny 8080/tcp",
            mitre_id="T1190",
            acao_bloqueio="Keep run blocked.",
        )

        details = LocalDashboard._format_finding_details(finding)

        self.assertIn("Detalhes do Risco (Red Team)", details)
        self.assertIn("High-level attack path.", details)
        self.assertIn("Passos para Correção (Blue Team)", details)
        self.assertIn("sudo ufw deny 8080/tcp", details)
        self.assertIn("Ação de Bloqueio Recomendada", details)
        self.assertIn("T1190", details)
        self.assertIn('"port": 8080', details)
        self.assertIn("Serviço local não aprovado", details)
        self.assertIn("Impacto prático:", details)
        self.assertIn("Evento: security.port.exposed", details)

    def test_plain_language_table_copy_preserves_technical_finding_data(self) -> None:
        finding = SecurityFinding(
            event_name="network.correlation.vulnerability_detected",
            severity="critical",
            summary="Plaintext HTTP traffic observed.",
            evidence={"port": 8080, "source": "nmap_tshark_offline_correlation"},
            vetor_ataque="Original technical attack vector.",
            remediacao="Enable TLS.",
            mitre_id="T1040",
            acao_bloqueio="Keep the run blocked.",
        )

        title, summary, next_step = LocalDashboard._plain_language_for_finding(
            finding
        )
        details = LocalDashboard._format_finding_details(finding)

        self.assertEqual(title, "Tráfego pode estar sem criptografia")
        self.assertIn("Dados poderiam ficar legíveis", summary)
        self.assertIn("Configure criptografia", next_step)
        self.assertIn("network.correlation.vulnerability_detected", details)
        self.assertIn("Original technical attack vector.", details)
        self.assertIn('"port": 8080', details)
        self.assertEqual(finding.mitre_id, "T1040")
        self.assertEqual(finding.evidence["port"], 8080)

    def test_automatic_mitigation_is_limited_to_trusted_repairable_baseline(self) -> None:
        repairable = SecurityFinding(
            event_name="integrity.hash.mismatch",
            severity="critical",
            summary="Hash mismatch.",
            evidence={"path": "config/dashboard.schema.json"},
            vetor_ataque="Altered file.",
            remediacao="Restore trusted baseline.",
            mitre_id="T1565.001",
            acao_bloqueio="Keep blocked.",
        )
        unsupported = SecurityFinding(
            event_name="integrity.hash.mismatch",
            severity="critical",
            summary="Hash mismatch.",
            evidence={"path": "schemas/scope.schema.json"},
            vetor_ataque="Altered file.",
            remediacao="Restore trusted baseline.",
            mitre_id="T1565.001",
            acao_bloqueio="Keep blocked.",
        )

        self.assertTrue(LocalDashboard._safe_mitigation_available(repairable))
        self.assertFalse(LocalDashboard._safe_mitigation_available(unsupported))
        self.assertFalse(LocalDashboard._safe_mitigation_available(None))

    def test_launch_gui_creates_dashboard_and_runs_event_loop(self) -> None:
        root = FakeRoot()
        with patch("sarr_core.gui.LocalDashboard") as dashboard:
            result = launch_gui(root_factory=lambda: root)  # type: ignore[arg-type]

        self.assertEqual(result, 0)
        self.assertTrue(root.mainloop_called)
        from sarr_core.simulation import LocalSimulationSession

        dashboard.assert_called_once_with(
            root, session_factory=LocalSimulationSession
        )

    def test_launch_gui_reports_missing_desktop_display(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "área de trabalho"):
            launch_gui(
                root_factory=lambda: (_ for _ in ()).throw(
                    tk.TclError("no display")
                )
            )


if __name__ == "__main__":
    unittest.main()
