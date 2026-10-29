"""Portable Tk dashboard for the local simulation and safety state."""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from sarr_core.simulation import LocalSimulationSession, SimulationSnapshot


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
        self._messages: queue.Queue[tuple[str, object]] = queue.Queue()

        root.title("SARR-Core Engine — painel local")
        root.minsize(520, 360)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        container = ttk.Frame(root, padding=16)
        container.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)

        ttk.Label(
            container,
            text="SARR-Core Engine",
            font=("TkDefaultFont", 16, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        self._state = tk.StringVar(value="IDLE")
        self._run_id = tk.StringVar(value="—")
        self._cpu = tk.StringVar(value="—")
        self._ram = tk.StringVar(value="—")
        self._rtt = tk.StringVar(value="—")
        self._message = tk.StringVar(value="Somente simulação local em 127.0.0.1.")

        self._add_value(container, 1, "Estado", self._state)
        self._add_value(container, 2, "run_id", self._run_id)
        self._add_value(container, 3, "CPU", self._cpu)
        self._add_value(container, 4, "RAM", self._ram)
        self._add_value(container, 5, "RTT", self._rtt)
        ttk.Label(
            container,
            textvariable=self._message,
            wraplength=480,
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 8))

        actions = ttk.Frame(container)
        actions.grid(row=7, column=0, columnspan=2, sticky="w")
        self._run_button = ttk.Button(
            actions,
            text="Executar simulação",
            command=self._start_simulation,
        )
        self._run_button.grid(row=0, column=0, padx=(0, 8))
        self._stop_button = ttk.Button(
            actions,
            text="Kill-switch",
            command=self._trigger_kill_switch,
            state=tk.DISABLED,
        )
        self._stop_button.grid(row=0, column=1)

        self._events = tk.Text(container, height=7, width=64, state=tk.DISABLED)
        self._events.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=(12, 0))
        container.rowconfigure(8, weight=1)

        self._root.after(100, self._poll)

    @staticmethod
    def _add_value(
        parent: ttk.Frame,
        row: int,
        label: str,
        value: tk.StringVar,
    ) -> None:
        ttk.Label(parent, text=f"{label}:").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Label(parent, textvariable=value).grid(
            row=row,
            column=1,
            sticky="w",
            padx=(12, 0),
            pady=3,
        )

    def _start_simulation(self) -> None:
        if self._worker is not None:
            return
        try:
            self._session = self._session_factory()
        except Exception as error:
            self._show_failure(error)
            return
        self._run_button.configure(state=tk.DISABLED)
        self._stop_button.configure(state=tk.NORMAL)
        self._state.set("VALIDATING")
        self._run_id.set(str(self._session.snapshot.run_id))
        worker = threading.Thread(
            target=self._run_worker,
            name="sarr-gui-simulation",
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
            self._state.set(session.snapshot.state.value)
            self._message.set("Kill-switch acionado; a simulação foi interrompida.")
            self._stop_button.configure(state=tk.DISABLED)
        except Exception as error:
            self._show_failure(error)

    def _poll(self) -> None:
        session = self._session
        if session is not None and self._worker is not None:
            try:
                self._update_snapshot(session.snapshot)
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
                    self._message.set("Simulação concluída.")
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
        self._state.set(snapshot.state.value)
        self._run_id.set(str(snapshot.run_id))
        telemetry = snapshot.telemetry
        if telemetry is not None:
            self._cpu.set(f"{telemetry.cpu_percent:.2f}%")
            self._ram.set(f"{telemetry.ram_percent:.2f}%")
            self._rtt.set(f"{telemetry.rtt_ms:.2f} ms")

    def _append_events(self) -> None:
        session = self._session
        if session is None:
            return
        self._events.configure(state=tk.NORMAL)
        self._events.delete("1.0", tk.END)
        for timestamp, name in session.event_log():
            self._events.insert(tk.END, f"{timestamp} {name}\n")
        self._events.configure(state=tk.DISABLED)

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
