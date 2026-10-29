"""Portable Tk SOC dashboard for local security-audit scenarios."""

import json
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from sarr_core.simulation import LocalSimulationSession, SimulationSnapshot


_CRITICAL_EVENTS = {
    "safety.triggered",
    "security.port.exposed",
    "security.permission.excessive",
    "integrity.hash.mismatch",
    "integrity.audit.failed",
    "auth.brute_force.detected",
}
_WARNING_EVENTS = {
    "security.permission.audit_unavailable",
    "security.permission.audit_failed",
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
        self._messages: queue.Queue[tuple[str, object]] = queue.Queue()

        root.title("SARR-Core Engine — SOC local")
        root.minsize(860, 620)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        container = ttk.Frame(root, padding=16)
        container.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(5, weight=1)
        container.rowconfigure(6, weight=1)

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
        self._posture = tk.StringVar(value="AUDIT PENDING")
        self._posture_label = ttk.Label(
            header,
            textvariable=self._posture,
            style="Posture.PENDING.TLabel",
            font=("TkDefaultFont", 12, "bold"),
        )
        self._posture_label.grid(row=0, column=2, sticky="e")

        details = ttk.Frame(container)
        details.grid(row=1, column=0, sticky="ew")
        details.columnconfigure(1, weight=1)
        self._state = tk.StringVar(value="IDLE")
        self._run_id = tk.StringVar(value="—")
        self._findings_count = tk.StringVar(value="0")
        self._add_value(details, 0, "Estado", self._state)
        self._add_value(details, 1, "run_id", self._run_id)
        self._add_value(details, 2, "Achados", self._findings_count)

        self._message = tk.StringVar(
            value="Auditoria offline: inventário local e fixtures sintéticas; sem sondagem de rede."
        )
        ttk.Label(
            container,
            textvariable=self._message,
            wraplength=800,
        ).grid(row=2, column=0, sticky="w", pady=(8, 10))

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

        findings_frame = ttk.LabelFrame(
            container,
            text="Findings / Descobertas",
            padding=8,
        )
        findings_frame.grid(row=5, column=0, sticky="nsew", pady=(0, 10))
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)
        self._findings_table = ttk.Treeview(
            findings_frame,
            columns=("severity", "event", "evidence"),
            show="headings",
            height=7,
        )
        self._findings_table.heading("severity", text="Severidade")
        self._findings_table.heading("event", text="Evento")
        self._findings_table.heading("evidence", text="Evidência")
        self._findings_table.column("severity", width=100, stretch=False)
        self._findings_table.column("event", width=220, stretch=False)
        self._findings_table.column("evidence", width=480, stretch=True)
        findings_scroll = ttk.Scrollbar(
            findings_frame,
            orient=tk.VERTICAL,
            command=self._findings_table.yview,
        )
        self._findings_table.configure(yscrollcommand=findings_scroll.set)
        self._findings_table.grid(row=0, column=0, sticky="nsew")
        findings_scroll.grid(row=0, column=1, sticky="ns")

        events_frame = ttk.LabelFrame(
            container,
            text="Console SIEM / Eventos",
            padding=8,
        )
        events_frame.grid(row=6, column=0, sticky="nsew")
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
    def _posture_for(
        state: str,
        finding_count: int,
        kill_switch_active: bool,
    ) -> tuple[str, str]:
        if kill_switch_active or state == "BLOCKED":
            return "ATTACK / KILL-SWITCH", "Posture.ATTACK.TLabel"
        if finding_count:
            return "VULNERABLE", "Posture.VULNERABLE.TLabel"
        if state == "COMPLETED":
            return "SECURE", "Posture.SECURE.TLabel"
        return "AUDIT PENDING", "Posture.PENDING.TLabel"

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
        for item in self._findings_table.get_children():
            self._findings_table.delete(item)
        self._findings_count.set("0")
        self._posture.set("AUDIT PENDING")
        self._posture_label.configure(style="Posture.PENDING.TLabel")
        self._run_button.configure(state=tk.DISABLED)
        self._stop_button.configure(state=tk.NORMAL)
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
        session = self._session
        events = session.event_log() if session is not None else ()
        kill_switch_active = any(name == "safety.triggered" for _, name in events)
        posture, style_name = self._posture_for(
            state,
            len(snapshot.findings),
            kill_switch_active,
        )
        self._posture.set(posture)
        self._posture_label.configure(style=style_name)
        self._render_findings(snapshot)

    def _render_findings(self, snapshot: SimulationSnapshot) -> None:
        for item in self._findings_table.get_children():
            self._findings_table.delete(item)
        for finding in snapshot.findings:
            evidence = json.dumps(
                finding.evidence,
                ensure_ascii=False,
                sort_keys=True,
            )
            self._findings_table.insert(
                "",
                tk.END,
                values=(
                    finding.severity.upper(),
                    finding.event_name,
                    evidence,
                ),
            )

    def _append_events(self) -> None:
        session = self._session
        if session is None:
            return
        events = session.event_log()
        new_events = events[self._rendered_event_count :]
        if not new_events:
            return
        self._events.configure(state=tk.NORMAL)
        for timestamp, event_name in new_events:
            severity = self._severity_for_event(event_name)
            self._events.insert(
                tk.END,
                f"{timestamp} [{severity}] {event_name}\n",
                severity,
            )
        self._events.see(tk.END)
        self._events.configure(state=tk.DISABLED)
        self._rendered_event_count = len(events)

    def _finish_worker(self) -> None:
        self._worker = None
        self._stop_button.configure(state=tk.DISABLED)
        self._run_button.configure(state=tk.NORMAL)

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
            "The local GUI could not start; verify that a desktop display is available."
        ) from error
    return 0


__all__ = ["LocalDashboard", "launch_gui"]
