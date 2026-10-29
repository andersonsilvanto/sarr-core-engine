"""Safe command-line entry points for the local SARR-Core engine."""

import argparse
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from core import (
    CoreOrchestrator,
    DataDirectoryError,
    KillSwitchTriggered,
    LocalDemoServer,
    LocalTelemetryProbe,
    OperationalLimitExceeded,
    RunState,
    Persistence,
    ScopeValidationError,
    ScopeValidator,
    TelemetryScenario,
    TelemetryUnavailable,
    resolve_data_directory,
)


def _print_status() -> None:
    print("SARR-Core Engine")
    print("Status: pronto")
    print(f"Estado da execução: {RunState.IDLE.value}")
    print("Kill-switch: inativo")


def _simulation_scope() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "engagement_id": "local-cli-demo",
        "environment": "local",
        "mode": "simulation",
        "valid_from_utc": (now - timedelta(seconds=1)).isoformat(),
        "valid_until_utc": (now + timedelta(minutes=5)).isoformat(),
        "allowed_targets": ["127.0.0.1"],
        "allowed_modules": ["telemetry_demo"],
        "limits": {
            "max_duration_seconds": 60,
            "max_rate_per_second": 2,
            "max_concurrency": 1,
            "max_volume_bytes": 16_384,
            "measurement_window_seconds": 10,
        },
    }


def _run_simulation() -> None:
    data_directory = resolve_data_directory()
    persistence = Persistence(
        data_directory / "sarr-core.sqlite3",
        data_directory / "audit.jsonl",
    )
    try:
        orchestrator = CoreOrchestrator(persistence=persistence)
        run = orchestrator.create_run("simulation")
        with tempfile.TemporaryDirectory(prefix="sarr-core-cli-") as directory:
            scope_path = Path(directory) / "scope.json"
            scope_path.write_text(
                json.dumps(_simulation_scope()),
                encoding="utf-8",
            )
            orchestrator.validate_scope(
                run.run_id,
                str(scope_path),
                engagement_id="local-cli-demo",
                environment="local",
                targets=["127.0.0.1"],
                modules=["telemetry_demo"],
                validator=ScopeValidator(kill_switch=orchestrator.kill_switch),
            )
            orchestrator.transition(run.run_id, RunState.RUNNING)
            with LocalDemoServer(
                TelemetryScenario.NORMAL_LATENCY,
                max_requests=1,
            ) as server:
                probe = LocalTelemetryProbe(
                    port=server.port,
                    run_id=run.run_id,
                    limits=orchestrator.get_operational_limits(run.run_id),
                    kill_switch=orchestrator.kill_switch,
                    event_bus=orchestrator.events,
                )
                sample = probe.sample()
            orchestrator.record_module_execution(run.run_id, "telemetry_demo")
            orchestrator.transition(run.run_id, RunState.COMPLETED)
        print("SARR-Core Engine - simulação local")
        print(f"run_id: {run.run_id}")
        print(f"Dados: {data_directory}")
        print("Destino: 127.0.0.1")
        print(
            "Telemetria: "
            f"CPU={sample.cpu_percent:.2f}% "
            f"RAM={sample.ram_percent:.2f}% "
            f"RTT={sample.rtt_ms:.2f}ms "
            f"drop={sample.drop_rate:.4f}"
        )
        for event in orchestrator.events.history:
            timestamp = event.timestamp_utc.isoformat().replace("+00:00", "Z")
            print(f"{timestamp} {event.name}")
        print(f"Estado final: {orchestrator.get_state(run.run_id).value}")
    finally:
        persistence.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sarr_core",
        description="Comandos locais de operação do SARR-Core Engine.",
    )
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument(
        "--status",
        action="store_true",
        help="exibe o status do motor sem iniciar execução",
    )
    commands.add_argument(
        "--run-sim",
        action="store_true",
        help="executa uma simulação de telemetria limitada a 127.0.0.1",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.status:
        _print_status()
        return 0

    try:
        _run_simulation()
    except (
        DataDirectoryError,
        KillSwitchTriggered,
        OperationalLimitExceeded,
        ScopeValidationError,
        TelemetryUnavailable,
        OSError,
        RuntimeError,
    ) as error:
        print(f"Execução bloqueada/falhou: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
