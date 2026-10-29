"""Portable Tk SOC dashboard for local security-audit scenarios."""

import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from core.security_audit import SecurityFinding
from sarr_core.simulation import (
    LocalSimulationSession,
    SimulationSnapshot,
    hardening_score,
    restore_known_baselines,
)
from sarr_core.scanner_bootstrap import ScannerBootstrap


_CRITICAL_EVENTS = {
    "safety.triggered",
    "security.port.exposed",
    "security.permission.excessive",
    "integrity.hash.mismatch",
    "integrity.baseline.missing",
    "integrity.audit.failed",
    "auth.brute_force.detected",
    "evasion.obfuscation.detected",
    "persistence.point.detected",
    "deception.canary.triggered",
    "deception.ghost_port.engaged",
    "network.correlation.vulnerability_detected",
}
_WARNING_EVENTS = {
    "security.permission.audit_unavailable",
    "security.permission.audit_failed",
    "external.scanner.failed",
}

_DETAIL_VAZIO = (
    "Nenhuma auditoria executada ainda. Clique em "
    '"Executar Varredura de Segurança" e depois selecione um achado '
    "para ver o risco (Red Team), a correção (Blue Team) e a ação de "
    "bloqueio recomendada."
)
_DETAIL_SELECIONE = (
    "Selecione um achado na tabela para ver o risco (Red Team), a correção "
    "(Blue Team) e a ação de bloqueio recomendada."
)

_PLAIN_LANGUAGE: dict[str, tuple[str, str, str]] = {
    "security.port.exposed": (
        "Serviço local não aprovado",
        "Um serviço está ativo sem autorização confirmada. Se não for necessário, pode ampliar o acesso ao computador.",
        "Confirme com a equipe responsável se o serviço deve permanecer ativo.",
    ),
    "integrity.hash.mismatch": (
        "Arquivo de configuração foi alterado",
        "O arquivo não corresponde à versão confiável. A configuração pode ter sido modificada.",
        "Mantenha a execução bloqueada e restaure somente de uma referência verificada.",
    ),
    "integrity.baseline.missing": (
        "Arquivo sem versão confiável",
        "Não há uma referência aprovada para comparar este arquivo; não é possível confirmar sua integridade.",
        "Verifique a origem do arquivo e aprove uma referência antes de liberar o sistema.",
    ),
    "integrity.audit.failed": (
        "Não foi possível verificar um arquivo",
        "A checagem de integridade falhou. Isso não prova adulteração, mas deixa o arquivo sem verificação.",
        "Corrija o acesso ao arquivo e execute a auditoria novamente.",
    ),
    "security.permission.excessive": (
        "Arquivo pode ser alterado por pessoas demais",
        "As permissões permitem escrita por grupo ou por todos, o que pode facilitar alterações não autorizadas.",
        "Revise quem realmente precisa de permissão de escrita antes de ajustar o acesso.",
    ),
    "security.permission.audit_unavailable": (
        "Permissões não foram verificadas",
        "Este ambiente não permitiu confirmar as permissões do arquivo; a postura não deve ser considerada totalmente verificada.",
        "Peça uma revisão manual das permissões e execute a auditoria novamente.",
    ),
    "security.permission.audit_failed": (
        "Falha ao verificar permissões",
        "A checagem de permissões falhou, então não foi possível confirmar quem pode alterar o arquivo.",
        "Mantenha a execução bloqueada até a checagem de permissões funcionar.",
    ),
    "auth.brute_force.detected": (
        "Muitas tentativas de acesso falharam",
        "Foram observadas tentativas repetidas de autenticação. Isso pode indicar erro de configuração ou tentativa de adivinhar uma senha.",
        "Verifique os registros de acesso e confirme se as tentativas são esperadas.",
    ),
    "evasion.obfuscation.detected": (
        "Conteúdo suspeito foi identificado",
        "Uma amostra local parece codificada ou disfarçada. Ela foi apenas analisada; nada foi executado.",
        "Revise a origem do arquivo antes de permitir seu uso.",
    ),
    "persistence.point.detected": (
        "Configuração sugere inicialização automática",
        "Um cenário de teste representa um mecanismo que poderia iniciar um programa automaticamente; nenhum mecanismo real foi alterado.",
        "Revise os itens de inicialização no sistema usando ferramentas administrativas aprovadas.",
    ),
    "deception.canary.triggered": (
        "Arquivo-isca foi acessado na simulação",
        "O marcador de teste foi acionado. O motor bloqueou a execução por precaução.",
        "Preserve os registros e confirme se o acesso veio de um teste autorizado.",
    ),
    "deception.ghost_port.engaged": (
        "Isca de rede sintética foi acionada",
        "Um cenário local simulou uma tentativa contra uma porta-isca. Nenhuma porta ou pacote real foi usado.",
        "Revise a origem do cenário e mantenha o bloqueio até confirmar que foi um teste autorizado.",
    ),
    "network.correlation.vulnerability_detected": (
        "Tráfego pode estar sem criptografia",
        "Uma captura offline mostrou protocolo em texto claro numa porta local identificada. Dados poderiam ficar legíveis no trajeto de rede.",
        "Configure criptografia no serviço e valide a correção com uma nova captura autorizada.",
    ),
    "network.nmap.port_discovered": (
        "Porta local está aberta",
        "O Nmap encontrou um serviço no próprio computador. A descoberta, sozinha, não confirma uma vulnerabilidade.",
        "Confirme se o serviço é necessário e se está autorizado.",
    ),
    "network.tshark.capture_analyzed": (
        "Captura offline analisada",
        "O Tshark verificou metadados da captura autorizada; o conteúdo dos pacotes não foi exportado.",
        "Revise os resultados no contexto do escopo autorizado.",
    ),
    "external.scanner.unavailable": (
        "Ferramenta de varredura externa não encontrada",
        "A auditoria continuou com verificações locais e sintéticas. A ausência da ferramenta de varredura não significa que o sistema esteja seguro.",
        "Instale a ferramenta somente se necessária e por um canal confiável.",
    ),
    "external.scanner.failed": (
        "A ferramenta de varredura externa não concluiu a checagem",
        "A auditoria continuou sem evidência válida dessa ferramenta; o resultado externo não foi tratado como seguro.",
        "Revise a instalação local da ferramenta e repita a checagem.",
    ),
}


class LocalDashboard:
    def __init__(
        self,
        root: tk.Tk,
        *,
        session_factory: Callable[[], LocalSimulationSession] = LocalSimulationSession,
    ) -> None:
        self._root = root
        self._session_factory = session_factory
        self._session: LocalSimulationSession | None = None
        self._worker: threading.Thread | None = None
        self._closing = False
        self._rendered_event_count = 0
        self._rendered_findings: tuple[SecurityFinding, ...] = ()
        self._rendered_healed_paths: tuple[str, ...] = ()
        self._finding_by_item: dict[str, SecurityFinding] = {}
        self._selected_finding: SecurityFinding | None = None
        self._messages: queue.Queue[tuple[str, object]] = queue.Queue()

        root.title("SARR-Core Engine — SOC local")
        root.minsize(860, 620)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        container = ttk.Frame(root, padding=16)
        container.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(5, weight=2)
        container.rowconfigure(6, weight=1)
        container.rowconfigure(7, weight=2)

        header = ttk.Frame(container)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)
        ttk.Label(
            header,
            text="SARR-Core Engine | SOC",
            font=("TkDefaultFont", 16, "bold"),
        ).grid(row=0, column=0, sticky="w")

        style = ttk.Style(root)
        style.configure("Posture.SECURE.TLabel", foreground="#16803c")
        style.configure("Posture.VULNERABLE.TLabel", foreground="#a85d00")
        style.configure("Posture.ATTACK.TLabel", foreground="#b42318")
        style.configure("Posture.PENDING.TLabel", foreground="#475467")
        self._posture = tk.StringVar(value="AUDITORIA PENDENTE")
        self._hardening_score = tk.StringVar(value="Índice de proteção: —/100")
        ttk.Label(
            header,
            textvariable=self._hardening_score,
            font=("TkDefaultFont", 11, "bold"),
        ).grid(row=0, column=1, sticky="e", padx=12)
        posture_indicator = ttk.Frame(header)
        posture_indicator.grid(row=0, column=2, sticky="e")
        self._traffic_light = tk.Canvas(
            posture_indicator,
            width=22,
            height=22,
            highlightthickness=0,
            background=root.cget("background"),
        )
        self._traffic_light.grid(row=0, column=0, padx=(0, 5))
        self._traffic_light_item = self._traffic_light.create_oval(
            3,
            3,
            19,
            19,
            fill="#667085",
            outline="#344054",
            width=1,
        )
        self._posture_label = ttk.Label(
            posture_indicator,
            textvariable=self._posture,
            style="Posture.PENDING.TLabel",
            font=("TkDefaultFont", 12, "bold"),
        )
        self._posture_label.grid(row=0, column=1, sticky="e")

        details = ttk.Frame(container)
        details.grid(row=1, column=0, sticky="ew")
        details.columnconfigure(1, weight=1)
        self._state = tk.StringVar(value="IDLE")
        self._run_id = tk.StringVar(value="—")
        self._findings_count = tk.StringVar(value="0")
        self._integrity_status = tk.StringVar(value="PENDENTE")
        self._scanner_status = tk.StringVar(value="PENDENTE")
        self._add_value(details, 0, "Estado", self._state)
        self._add_value(details, 1, "run_id", self._run_id)
        self._add_value(details, 2, "Achados", self._findings_count)
        self._add_value(details, 3, "Integridade dinâmica", self._integrity_status)
        self._add_value(details, 4, "Ferramentas (Nmap + Tshark)", self._scanner_status)

        self._message = tk.StringVar(
            value=(
                "Auditoria local: cenários sintéticos; Nmap limitado a 127.0.0.1 "
                "quando disponível; Tshark somente em captura offline."
            )
        )
        self._message_label = ttk.Label(
            container,
            textvariable=self._message,
            wraplength=800,
        )
        self._message_label.grid(row=2, column=0, sticky="w", pady=(8, 10))
        container.bind("<Configure>", self._resize_message_wrap)

        actions = ttk.Frame(container)
        actions.grid(row=3, column=0, sticky="w", pady=(0, 10))
        self._run_button = ttk.Button(
            actions,
            text="Executar Varredura de Segurança",
            command=self._start_simulation,
        )
        self._run_button.grid(row=0, column=0, padx=(0, 8))
        self._stop_button = ttk.Button(
            actions,
            text="Acionar Kill-Switch Manual",
            command=self._trigger_kill_switch,
            state=tk.DISABLED,
        )
        self._stop_button.grid(row=0, column=1)
        self._fix_button = ttk.Button(
            actions,
            text="Restaurar referências",
            command=self._start_remediation,
            state=tk.DISABLED,
        )
        self._fix_button.grid(row=0, column=2, padx=(8, 0))
        self._export_button = ttk.Button(
            actions,
            text="Exportar relatório executivo",
            command=self._export_executive_report,
            state=tk.DISABLED,
        )
        self._export_button.grid(row=0, column=3, padx=(8, 0))
        self._bootstrap_button = ttk.Button(
            actions,
            text="Verificar ferramentas de varredura",
            command=self._bootstrap_scanners,
        )
        self._bootstrap_button.grid(row=1, column=0, sticky="w", pady=(8, 0))

        findings_frame = ttk.LabelFrame(
            container,
            text="Achados",
            padding=8,
        )
        findings_frame.grid(row=5, column=0, sticky="nsew", pady=(0, 10))
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)
        self._findings_table = ttk.Treeview(
            findings_frame,
            columns=("severity", "event", "mitre", "status", "summary"),
            show="headings",
            height=7,
        )
        self._findings_table.tag_configure("CRITICAL", foreground="#b42318")
        self._findings_table.tag_configure("WARNING", foreground="#a85d00")
        self._findings_table.tag_configure("INFO", foreground="#344054")
        self._findings_table.heading("severity", text="Severidade")
        self._findings_table.heading("event", text="Evento")
        self._findings_table.heading("mitre", text="MITRE ATT&CK")
        self._findings_table.heading("status", text="Status")
        self._findings_table.heading("summary", text="Resumo")
        self._findings_table.column("severity", width=100, stretch=False)
        self._findings_table.column("event", width=220, stretch=False)
        self._findings_table.column("mitre", width=110, stretch=False)
        self._findings_table.column("status", width=145, stretch=False)
        self._findings_table.column("summary", width=420, stretch=True)
        self._findings_table.bind(
            "<<TreeviewSelect>>",
            self._show_selected_finding,
        )
        findings_scroll = ttk.Scrollbar(
            findings_frame,
            orient=tk.VERTICAL,
            command=self._findings_table.yview,
        )
        self._findings_table.configure(yscrollcommand=findings_scroll.set)
        self._findings_table.grid(row=0, column=0, sticky="nsew")
        findings_scroll.grid(row=0, column=1, sticky="ns")

        detail_frame = ttk.LabelFrame(
            container,
            text="Análise e resposta do achado selecionado",
            padding=8,
        )
        detail_frame.grid(row=6, column=0, sticky="nsew", pady=(0, 10))
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)
        self._finding_details = tk.Text(
            detail_frame,
            height=8,
            width=100,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        detail_scroll = ttk.Scrollbar(
            detail_frame,
            orient=tk.VERTICAL,
            command=self._finding_details.yview,
        )
        self._finding_details.configure(yscrollcommand=detail_scroll.set)
        self._finding_details.grid(row=0, column=0, sticky="nsew")
        detail_scroll.grid(row=0, column=1, sticky="ns")
        detail_actions = ttk.Frame(detail_frame)
        detail_actions.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._copy_recommendation_button = ttk.Button(
            detail_actions,
            text="Copiar orientação",
            command=self._copy_selected_recommendation,
            state=tk.DISABLED,
        )
        self._copy_recommendation_button.grid(row=0, column=0, padx=(0, 8))
        self._safe_mitigation_button = ttk.Button(
            detail_actions,
            text="Aplicar mitigação segura",
            command=self._apply_selected_safe_mitigation,
            state=tk.DISABLED,
        )
        self._safe_mitigation_button.grid(row=0, column=1)
        self._set_finding_details(_DETAIL_VAZIO)

        events_frame = ttk.LabelFrame(
            container,
            text="Console SIEM — eventos",
            padding=8,
        )
        events_frame.grid(row=7, column=0, sticky="nsew")
        events_frame.columnconfigure(0, weight=1)
        events_frame.rowconfigure(0, weight=1)
        self._events = tk.Text(
            events_frame,
            height=9,
            width=100,
            state=tk.DISABLED,
            wrap=tk.NONE,
        )
        self._events.tag_configure("INFO", foreground="#344054")
        self._events.tag_configure("WARNING", foreground="#a85d00")
        self._events.tag_configure("CRITICAL", foreground="#b42318")
        events_scroll = ttk.Scrollbar(
            events_frame,
            orient=tk.VERTICAL,
            command=self._events.yview,
        )
        self._events.configure(yscrollcommand=events_scroll.set)
        self._events.grid(row=0, column=0, sticky="nsew")
        events_scroll.grid(row=0, column=1, sticky="ns")
        self._append_console_line(
            "SARR-Core pronto. Nenhuma auditoria executada.",
            "INFO",
        )

        self._root.after(100, self._poll)

    @staticmethod
    def _add_value(
        parent: ttk.Frame,
        row: int,
        label: str,
        value: tk.StringVar,
    ) -> None:
        ttk.Label(parent, text=f"{label}:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Label(parent, textvariable=value).grid(
            row=row,
            column=1,
            sticky="w",
            padx=(12, 0),
            pady=2,
        )

    @staticmethod
    def _severity_for_event(event_name: str) -> str:
        if event_name in _CRITICAL_EVENTS:
            return "CRITICAL"
        if event_name in _WARNING_EVENTS:
            return "WARNING"
        return "INFO"

    @staticmethod
    def _severity_label(severity: str) -> str:
        return {
            "CRITICAL": "CRÍTICO",
            "WARNING": "ATENÇÃO",
            "INFO": "INFORMATIVO",
        }.get(severity.upper(), "INFORMATIVO")

    @staticmethod
    def _integrity_status_for(snapshot: SimulationSnapshot) -> str:
        if snapshot.healed_paths:
            return "RESTAURADO / CORRIGIDO"
        if snapshot.state.value == "COMPLETED":
            return "VERIFICADO"
        if snapshot.state.value == "BLOCKED":
            return "NÃO VERIFICADO / FAIL-CLOSED"
        return "VERIFICANDO"

    @staticmethod
    def _scanner_pipeline_status_for(snapshot: SimulationSnapshot) -> str:
        statuses = dict(snapshot.scanner_status)
        nmap_ready = statuses.get("Nmap", "").startswith("disponível")
        tshark_ready = statuses.get("Tshark", "").startswith(
            ("disponível", "análise offline concluída")
        )
        if nmap_ready and tshark_ready:
            return "PRONTO — Nmap em 127.0.0.1 + Tshark offline"
        if statuses:
            return "ALTERNATIVO — simulação interna ativa"
        return "NÃO VERIFICADO"

    @staticmethod
    def _posture_for(
        state: str,
        finding_count: int,
        kill_switch_active: bool,
    ) -> tuple[str, str]:
        if kill_switch_active or state == "BLOCKED":
            return "ATAQUE / KILL-SWITCH", "Posture.ATTACK.TLabel"
        if finding_count:
            return "VULNERÁVEL", "Posture.VULNERABLE.TLabel"
        if state == "COMPLETED":
            return "SEGURO", "Posture.SECURE.TLabel"
        return "AUDITORIA PENDENTE", "Posture.PENDING.TLabel"

    @staticmethod
    def _row_tag_for_severity(severity: str) -> str:
        normalized = severity.lower()
        if normalized in {"critical", "high"}:
            return "CRITICAL"
        if normalized in {"medium", "warning"}:
            return "WARNING"
        return "INFO"

    def _resize_message_wrap(self, event: tk.Event) -> None:
        self._message_label.configure(wraplength=max(320, event.width - 40))

    @staticmethod
    def _traffic_color_for(style_name: str) -> str:
        return {
            "Posture.SECURE.TLabel": "#16803c",
            "Posture.VULNERABLE.TLabel": "#eab308",
            "Posture.ATTACK.TLabel": "#b42318",
        }.get(style_name, "#667085")

    @staticmethod
    def _plain_language_for_finding(
        finding: SecurityFinding,
    ) -> tuple[str, str, str]:
        title, impact, next_step = _PLAIN_LANGUAGE.get(
            finding.event_name,
            (
                finding.event_name.replace(".", " ").replace("_", " ").capitalize(),
                finding.summary,
                finding.remediacao,
            ),
        )
        evidence = finding.evidence
        if finding.event_name in {
            "security.port.exposed",
            "network.nmap.port_discovered",
        }:
            port = evidence.get("port")
            service = evidence.get("service")
            location = (
                f" (porta {port}, serviço {service})"
                if isinstance(port, int) and isinstance(service, str)
                else ""
            )
            impact = impact.rstrip(".") + location + "."
        elif finding.event_name in {
            "integrity.hash.mismatch",
            "integrity.baseline.missing",
            "integrity.audit.failed",
            "security.permission.excessive",
            "security.permission.audit_unavailable",
            "security.permission.audit_failed",
        }:
            path = evidence.get("path")
            if isinstance(path, str):
                impact = impact.rstrip(".") + f". Arquivo: {path}."
        return title, impact, next_step

    @staticmethod
    def _safe_mitigation_available(finding: SecurityFinding | None) -> bool:
        return (
            finding is not None
            and finding.event_name == "integrity.hash.mismatch"
            and finding.evidence.get("path") == "config/dashboard.schema.json"
        )

    def _start_simulation(self) -> None:
        if self._worker is not None:
            return
        try:
            self._session = self._session_factory()
        except Exception as error:
            self._show_failure(error)
            return
        self._rendered_event_count = 0
        self._events.configure(state=tk.NORMAL)
        self._events.delete("1.0", tk.END)
        self._events.configure(state=tk.DISABLED)
        self._append_console_line("Auditoria iniciada.", "INFO")
        for item in self._findings_table.get_children():
            self._findings_table.delete(item)
        self._finding_by_item.clear()
        self._selected_finding = None
        self._copy_recommendation_button.configure(state=tk.DISABLED)
        self._safe_mitigation_button.configure(state=tk.DISABLED)
        self._rendered_findings = ()
        self._set_finding_details("Auditoria em andamento...")
        self._findings_count.set("0")
        self._integrity_status.set("VERIFICANDO")
        self._scanner_status.set("Verificando ferramentas...")
        self._hardening_score.set("Índice de proteção: —/100")
        self._posture.set("AUDITORIA PENDENTE")
        self._posture_label.configure(style="Posture.PENDING.TLabel")
        self._traffic_light.itemconfigure(
            self._traffic_light_item,
            fill=self._traffic_color_for("Posture.PENDING.TLabel"),
        )
        self._run_button.configure(state=tk.DISABLED)
        self._stop_button.configure(state=tk.NORMAL)
        self._fix_button.configure(state=tk.DISABLED)
        self._export_button.configure(state=tk.DISABLED)
        self._state.set("VALIDATING")
        self._run_id.set(str(self._session.snapshot.run_id))
        worker = threading.Thread(
            target=self._run_worker,
            name="sarr-gui-security-audit",
            daemon=True,
        )
        self._worker = worker
        worker.start()

    def _run_worker(self) -> None:
        session = self._session
        if session is None:
            return
        try:
            snapshot = session.run()
            self._messages.put(("completed", snapshot))
        except Exception as error:
            self._messages.put(("failed", error))

    def _trigger_kill_switch(self) -> None:
        session = self._session
        if session is None:
            return
        try:
            session.stop()
            self._update_snapshot(session.snapshot)
            self._append_events()
            self._message.set("Kill-switch acionado; a execução foi bloqueada.")
            self._stop_button.configure(state=tk.DISABLED)
        except Exception as error:
            self._show_failure(error)

    def _copy_selected_recommendation(self) -> None:
        selected = self._selected_finding
        if selected is None:
            return
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append(selected.remediacao)
        except tk.TclError as error:
            self._show_failure(error)
            return
        self._message.set("Orientação de correção copiada para a área de transferência.")

    def _apply_selected_safe_mitigation(self) -> None:
        if not self._safe_mitigation_available(self._selected_finding):
            return
        if not messagebox.askyesno(
            "Aplicar mitigação segura",
            "Restaurar config/dashboard.schema.json usando somente a referência "
            "SHA-256 aprovada e depois repetir a auditoria?",
            parent=self._root,
        ):
            return
        self._start_remediation(confirmed=True)

    def _bootstrap_scanners(self) -> None:
        try:
            installations = ScannerBootstrap().inspect()
            guidance = ScannerBootstrap.installation_guidance(installations)
        except (OSError, ValueError) as error:
            self._show_failure(error)
            return

        lines = [
            f"{item.name}: {item.executable or 'não encontrado'}"
            for item in installations
        ]
        lines.extend(guidance)
        if not guidance:
            lines.append("Ferramentas encontradas. Nmap permanece restrito a 127.0.0.1.")
        message = "\n".join(lines)
        self._message.set("Verificação de ferramentas concluída.")
        messagebox.showinfo(
            "Ferramentas de varredura (Nmap + Tshark)",
            message,
            parent=self._root,
        )

    def _export_executive_report(self) -> None:
        session = self._session
        if session is None:
            return
        report_format = messagebox.askyesnocancel(
            "Exportar relatório executivo",
            "Sim: JSON\nNão: Markdown\nCancelar: voltar",
            parent=self._root,
        )
        if report_format is None:
            return
        extension = ".json" if report_format else ".md"
        filetypes = (
            (("JSON", "*.json"), ("Todos os arquivos", "*.*"))
            if report_format
            else (("Markdown", "*.md"), ("Todos os arquivos", "*.*"))
        )
        destination = filedialog.asksaveasfilename(
            parent=self._root,
            title="Salvar relatório executivo",
            initialdir=str(session.data_directory),
            initialfile=f"{session.snapshot.run_id}-executivo{extension}",
            defaultextension=extension,
            filetypes=filetypes,
        )
        if not destination:
            return
        try:
            exported = session.export_executive_report(
                destination,
                format="json" if report_format else "markdown",
            )
        except Exception as error:
            self._show_failure(error)
            return
        self._message.set(f"Relatório executivo exportado: {exported}")

    def _start_remediation(self, *, confirmed: bool = False) -> None:
        if self._worker is not None:
            return
        if not confirmed and not messagebox.askyesno(
            "Restaurar referência",
            "A ação restaura somente config/dashboard.schema.json a partir do "
            "schema de origem verificado. Deseja continuar?",
            parent=self._root,
        ):
            return
        self._run_button.configure(state=tk.DISABLED)
        self._stop_button.configure(state=tk.DISABLED)
        self._fix_button.configure(state=tk.DISABLED)
        self._message.set("Validando origem confiável e restaurando a referência...")
        worker = threading.Thread(
            target=self._remediation_worker,
            name="sarr-gui-baseline-remediation",
            daemon=True,
        )
        self._worker = worker
        worker.start()

    def _remediation_worker(self) -> None:
        session: LocalSimulationSession | None = None
        try:
            restored_paths = restore_known_baselines()
            session = self._session_factory()
            snapshot = session.run()
            self._messages.put(
                ("remediated", (restored_paths, snapshot, session))
            )
        except Exception as error:
            if session is not None:
                session.close()
            self._messages.put(("failed", error))

    def _poll(self) -> None:
        session = self._session
        if session is not None and self._worker is not None:
            try:
                self._update_snapshot(session.snapshot)
                self._append_events()
            except Exception as error:
                self._messages.put(("failed", error))

        try:
            while True:
                kind, value = self._messages.get_nowait()
                if kind == "completed":
                    snapshot = value
                    if isinstance(snapshot, SimulationSnapshot):
                        self._update_snapshot(snapshot)
                    self._append_events()
                    self._message.set(
                        "Execução bloqueada por achado crítico."
                        if isinstance(snapshot, SimulationSnapshot)
                        and snapshot.state.value == "BLOCKED"
                        else "Auditoria defensiva concluída."
                    )
                    self._finish_worker()
                elif kind == "remediated":
                    restored_paths, snapshot, remediated_session = value
                    if not isinstance(snapshot, SimulationSnapshot):
                        raise TypeError(
                            "A restauração retornou um resultado de auditoria inválido."
                        )
                    self._session = remediated_session
                    self._rendered_event_count = 0
                    self._update_snapshot(snapshot)
                    self._append_events()
                    restored = ", ".join(
                        path.as_posix() for path in restored_paths
                    ) or "nenhum arquivo precisava de restauração"
                    self._message.set(
                        f"Referência restaurada ({restored}); auditoria de confirmação "
                        f"concluída com índice {snapshot.hardening_score}/100."
                    )
                    self._finish_worker()
                elif kind == "failed" and isinstance(value, Exception):
                    if session is not None:
                        try:
                            self._update_snapshot(session.snapshot)
                        except Exception:
                            self._state.set("FAILED")
                    self._append_events()
                    self._show_failure(value)
                    self._finish_worker()
        except queue.Empty:
            pass

        if self._closing:
            worker = self._worker
            if worker is None or not worker.is_alive():
                session = self._session
                if session is not None:
                    session.close()
                self._root.destroy()
                return
        self._root.after(100, self._poll)

    def _update_snapshot(self, snapshot: SimulationSnapshot) -> None:
        state = snapshot.state.value
        self._state.set(state)
        self._run_id.set(str(snapshot.run_id))
        self._findings_count.set(str(len(snapshot.findings)))
        self._hardening_score.set(
            f"Índice de proteção: {hardening_score(snapshot.findings)}/100"
        )
        self._integrity_status.set(self._integrity_status_for(snapshot))
        self._scanner_status.set(self._scanner_pipeline_status_for(snapshot))
        session = self._session
        events = session.event_log() if session is not None else ()
        kill_switch_active = any(name == "safety.triggered" for _, name in events)
        posture, style_name = self._posture_for(
            state,
            sum(finding.severity.lower() != "info" for finding in snapshot.findings),
            kill_switch_active,
        )
        self._posture.set(posture)
        self._posture_label.configure(style=style_name)
        self._traffic_light.itemconfigure(
            self._traffic_light_item,
            fill=self._traffic_color_for(style_name),
        )
        self._render_findings(snapshot)

    def _render_findings(self, snapshot: SimulationSnapshot) -> None:
        if (
            snapshot.findings == self._rendered_findings
            and snapshot.healed_paths == self._rendered_healed_paths
        ):
            return
        for item in self._findings_table.get_children():
            self._findings_table.delete(item)
        self._finding_by_item.clear()
        self._rendered_findings = snapshot.findings
        self._rendered_healed_paths = snapshot.healed_paths
        if snapshot.healed_paths:
            healed_tag = self._row_tag_for_severity("info")
            self._findings_table.insert(
                "",
                tk.END,
                iid="integrity-healed",
                values=(
                    "INFORMATIVO",
                    "security.state.healed",
                    "Não se aplica",
                    "RESTAURADO / CORRIGIDO",
                    ", ".join(snapshot.healed_paths),
                ),
                tags=(healed_tag,),
            )
        for index, finding in enumerate(snapshot.findings):
            item_id = f"finding-{index}"
            self._finding_by_item[item_id] = finding
            title, summary, _ = self._plain_language_for_finding(finding)
            row_tag = self._row_tag_for_severity(finding.severity)
            self._findings_table.insert(
                "",
                tk.END,
                iid=item_id,
                values=(
                    self._severity_label(row_tag),
                    title,
                    finding.mitre_id or "Não se aplica",
                    "Revisar" if finding.severity.lower() != "info" else "Informativo",
                    summary,
                ),
                tags=(row_tag,),
            )
        if snapshot.findings:
            first_item = "finding-0"
            self._findings_table.selection_set(first_item)
            self._findings_table.focus(first_item)
            self._show_selected_finding()
        elif snapshot.healed_paths:
            self._findings_table.selection_set("integrity-healed")
            self._findings_table.focus("integrity-healed")
            self._show_selected_finding()
        else:
            self._set_finding_details("Nenhum achado nesta auditoria.")

    def _show_selected_finding(self, _event: object = None) -> None:
        selected = self._findings_table.selection()
        if not selected:
            self._selected_finding = None
            self._copy_recommendation_button.configure(state=tk.DISABLED)
            self._safe_mitigation_button.configure(state=tk.DISABLED)
            self._set_finding_details(_DETAIL_SELECIONE)
            return
        finding = self._finding_by_item.get(selected[0])
        if finding is None:
            self._selected_finding = None
            self._copy_recommendation_button.configure(state=tk.DISABLED)
            self._safe_mitigation_button.configure(state=tk.DISABLED)
            if selected[0] == "integrity-healed":
                self._set_finding_details(
                    "Integridade restaurada a partir de uma cópia de referência "
                    "protegida em memória, verificada por SHA-256. Nenhum byte "
                    "adulterado foi mantido."
                )
            return
        self._selected_finding = finding
        self._copy_recommendation_button.configure(state=tk.NORMAL)
        self._safe_mitigation_button.configure(
            state=(
                tk.NORMAL
                if self._safe_mitigation_available(finding)
                else tk.DISABLED
            )
        )
        self._set_finding_details(self._format_finding_details(finding))

    @staticmethod
    def _format_finding_details(finding: SecurityFinding) -> str:
        title, impact, next_step = LocalDashboard._plain_language_for_finding(finding)
        return (
            f"Em poucas palavras: {title}\n\n"
            f"Impacto prático: {impact}\n\n"
            f"Próximo passo: {next_step}\n\n"
            "Detalhes técnicos para auditoria\n"
            f"Evento: {finding.event_name}\n"
            f"Severidade: {LocalDashboard._severity_label(finding.severity)}\n"
            f"MITRE ATT&CK: {finding.mitre_id or 'Não se aplica'}\n"
            "Evidência observada\n"
            f"{json.dumps(finding.evidence, ensure_ascii=False, sort_keys=True)}\n\n"
            f"Detalhes do Risco (Red Team)\n{finding.vetor_ataque}\n\n"
            f"Passos para Correção (Blue Team)\n{finding.remediacao}\n\n"
            f"Ação de Bloqueio Recomendada\n{finding.acao_bloqueio}"
        )

    def _set_finding_details(self, text: str) -> None:
        self._finding_details.configure(state=tk.NORMAL)
        self._finding_details.delete("1.0", tk.END)
        self._finding_details.insert(tk.END, text)
        self._finding_details.configure(state=tk.DISABLED)

    def _append_events(self) -> None:
        session = self._session
        if session is None:
            return
        events = session.event_log()
        new_events = events[self._rendered_event_count :]
        if not new_events:
            return
        for timestamp, event_name in new_events:
            severity = self._severity_for_event(event_name)
            display_name = {
                "deception.canary.triggered": "ALERTA DE ARQUIVO-ISCA",
                "deception.ghost_port.engaged": "ALERTA DE ISCA SINTÉTICA",
                "evasion.obfuscation.detected": "OFUSCAÇÃO DETECTADA",
                "persistence.point.detected": "PERSISTÊNCIA SINTÉTICA DETECTADA",
                "security.state.healed": "STATUS: RESTAURADO / CORRIGIDO",
                "external.scanner.unavailable": "AVISO: FERRAMENTA DE VARREDURA AUSENTE",
                "network.correlation.vulnerability_detected": (
                    "CRÍTICO: CORRELAÇÃO NMAP + TSHARK"
                ),
            }.get(event_name, event_name)
            self._append_console_line(
                f"{timestamp} {display_name}",
                severity,
            )
        self._rendered_event_count = len(events)

    def _append_console_line(self, text: str, severity: str) -> None:
        self._events.configure(state=tk.NORMAL)
        self._events.insert(
            tk.END,
            f"[{self._severity_label(severity)}] {text}\n",
            severity,
        )
        self._events.see(tk.END)
        self._events.configure(state=tk.DISABLED)

    def _finish_worker(self) -> None:
        self._worker = None
        self._stop_button.configure(state=tk.DISABLED)
        self._run_button.configure(state=tk.NORMAL)
        self._fix_button.configure(state=tk.NORMAL)
        self._export_button.configure(
            state=(
                tk.NORMAL
                if self._session is not None
                and self._session.has_executive_report
                else tk.DISABLED
            )
        )

    def _show_failure(self, error: Exception) -> None:
        self._message.set(f"Falha/execução bloqueada: {error}")
        messagebox.showerror("SARR-Core — falha", str(error), parent=self._root)

    def _on_close(self) -> None:
        self._closing = True
        session = self._session
        if session is not None:
            try:
                session.stop()
            except Exception as error:
                self._show_failure(error)
            if self._worker is None:
                session.close()
                self._root.destroy()


def launch_gui(*, root_factory: Callable[[], tk.Tk] = tk.Tk) -> int:
    try:
        root = root_factory()
        LocalDashboard(root)
        root.mainloop()
    except tk.TclError as error:
        raise RuntimeError(
            "A interface gráfica local não pôde iniciar; verifique se há uma área "
            "de trabalho disponível."
        ) from error
    return 0


__all__ = ["LocalDashboard", "launch_gui"]
