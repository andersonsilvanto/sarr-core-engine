"""Safe command-line entry points for the local SARR-Core engine."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from core import (
    DataDirectoryError,
    KillSwitchTriggered,
    OperationalLimitExceeded,
    RunState,
    ScopeValidationError,
    TelemetryUnavailable,
    resolve_data_directory,
)
from sarr_core.metadata import MetadataExportError, MetadataManager
from sarr_core.simulation import LocalSimulationSession


def _print_status() -> None:
    print("SARR-Core Engine")
    print("Status: pronto")
    print(f"Estado da execução: {RunState.IDLE.value}")
    print("Kill-switch: inativo")


def _run_simulation() -> None:
    session = LocalSimulationSession()
    try:
        snapshot = session.run()
        sample = snapshot.telemetry
        if sample is None:
            raise RuntimeError("Simulation completed without a telemetry sample.")
        print("SARR-Core Engine - simulação local")
        print(f"run_id: {snapshot.run_id}")
        print(f"Dados: {session.data_directory}")
        print("Destino: 127.0.0.1")
        print(
            "Telemetria: "
            f"CPU={sample.cpu_percent:.2f}% "
            f"RAM={sample.ram_percent:.2f}% "
            f"RTT={sample.rtt_ms:.2f}ms "
            f"drop={sample.drop_rate:.4f}"
        )
        for timestamp, event_name in session.event_log():
            print(f"{timestamp} {event_name}")
        print(f"Estado final: {snapshot.state.value}")
    finally:
        session.close()


def _export_metadata() -> Path:
    data_directory = resolve_data_directory()
    output_path = data_directory / "exports" / "metadata-latest.json"
    exported_path = MetadataManager(
        data_directory / "sarr-core.sqlite3"
    ).export_latest_run(output_path)
    print(f"Metadata da última execução exportado: {exported_path}")
    return exported_path


def _export_dashboard() -> Path:
    project_root = Path(__file__).resolve().parents[2]
    source_schema = project_root / "schemas" / "dashboard.schema.json"
    if not source_schema.is_file():
        source_schema = Path(sys.prefix) / "schemas" / "dashboard.schema.json"
    if not source_schema.is_file():
        raise FileNotFoundError(f"Dashboard schema not found: {source_schema}")

    schema_document = json.loads(source_schema.read_text(encoding="utf-8"))
    if not isinstance(schema_document, dict):
        raise ValueError("Dashboard schema must be a JSON object.")
    Draft202012Validator.check_schema(schema_document)
    output_path = project_root / "config" / "dashboard.schema.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(
                schema_document,
                stream,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    print(f"Schema JSON do dashboard exportado: {output_path}")
    return output_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sarr_core",
        description="Comandos locais de operação do SARR-Core Engine.",
    )
    commands = parser.add_mutually_exclusive_group()
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
    commands.add_argument(
        "--gui",
        action="store_true",
        help="abre o painel gráfico local da simulação",
    )
    parser.add_argument(
        "--export-metadata",
        action="store_true",
        help="exporta os metadados da última execução persistida em JSON",
    )
    parser.add_argument(
        "--export-dashboard",
        action="store_true",
        help="exporta o schema JSON do dashboard para config/",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.status:
        _print_status()
    try:
        if arguments.run_sim:
            _run_simulation()
        if arguments.export_metadata:
            _export_metadata()
        if arguments.export_dashboard:
            _export_dashboard()
        if arguments.gui:
            from sarr_core.gui import launch_gui

            return launch_gui()
        if not (
            arguments.status
            or arguments.run_sim
            or arguments.gui
            or arguments.export_metadata
            or arguments.export_dashboard
        ):
            _print_status()
    except (
        DataDirectoryError,
        KillSwitchTriggered,
        MetadataExportError,
        OperationalLimitExceeded,
        ScopeValidationError,
        TelemetryUnavailable,
        ImportError,
        OSError,
        RuntimeError,
        SchemaError,
        ValueError,
    ) as error:
        print(f"Execução bloqueada/falhou: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
