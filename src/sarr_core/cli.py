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
    resolve_data_directory,
)
from sarr_core.metadata import MetadataExportError, MetadataManager
from sarr_core.scanner_bootstrap import ScannerBootstrap
from sarr_core.simulation import (
    LocalSimulationSession,
    SecurityScenario,
)


def _print_status() -> None:
    print("SARR-Core Engine")
    print("Status: pronto")
    print(f"Estado da execução: {RunState.IDLE.value}")
    print("Kill-switch: inativo")


def _run_simulation(
    scenario: SecurityScenario,
    *,
    tshark_capture: Path | None = None,
) -> int:
    session = LocalSimulationSession(scenario, tshark_capture=tshark_capture)
    try:
        snapshot = session.run()
        print("SARR-Core Engine - auditoria defensiva local")
        print(f"run_id: {snapshot.run_id}")
        print(f"Dados: {session.data_directory}")
        print(f"Cenário: {scenario.value}")
        print(f"Hardening Score: {snapshot.hardening_score}/100")
        print(
            "Evidências: fixtures locais/sintéticas; Nmap limitado a 127.0.0.1 "
            "quando disponível; Tshark apenas em captura offline autorizada."
        )
        for tool, status in snapshot.scanner_status:
            print(f"Ferramenta externa — {tool}: {status}")
        for finding in snapshot.findings:
            if finding.event_name in {
                "external.scanner.unavailable",
                "external.scanner.failed",
            }:
                print(f"Aviso: {finding.summary}")
            print(
                f"Achado [{finding.severity}] {finding.event_name} "
                f"(MITRE {finding.mitre_id or 'N/A'}): {finding.summary}"
            )
            print(f"  Vetor Red Team: {finding.vetor_ataque}")
            print(f"  Remediação Blue Team: {finding.remediacao}")
            print(f"  Bloqueio recomendado: {finding.acao_bloqueio}")
        for timestamp, event_name in session.event_log():
            print(f"{timestamp} {event_name}")
        print(f"Estado final: {snapshot.state.value}")
        return 2 if snapshot.state is RunState.BLOCKED else 0
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


def _bootstrap_scanners() -> None:
    bootstrap = ScannerBootstrap()
    installations = bootstrap.inspect()
    print("SARR-Core — verificação local de scanners")
    for installation in installations:
        status = (
            str(installation.executable)
            if installation.executable is not None
            else "não encontrado"
        )
        print(f"{installation.name}: {status}")
    guidance = bootstrap.installation_guidance(installations)
    if guidance:
        print("\n".join(guidance))
    else:
        print("Nmap e Tshark estão disponíveis; Nmap será limitado ao loopback.")


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
        help="executa uma auditoria defensiva offline com evidências locais/sintéticas",
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
    parser.add_argument(
        "--bootstrap-scanners",
        action="store_true",
        help=(
            "verifica Nmap/Tshark locais e exibe instruções opcionais; "
            "não baixa nem executa instaladores"
        ),
    )
    parser.add_argument(
        "--scenario",
        choices=tuple(scenario.value for scenario in SecurityScenario),
        default=SecurityScenario.NORMAL.value,
        help="cenário sintético para --run-sim",
    )
    parser.add_argument(
        "--tshark-capture",
        type=Path,
        help=(
            "analisa offline um .pcap/.pcapng dentro da pasta do projeto; "
            "captura ao vivo não é suportada"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.tshark_capture is not None and not arguments.run_sim:
        parser.error("--tshark-capture requires --run-sim")
    if arguments.status:
        _print_status()
    try:
        if arguments.run_sim:
            return_code = _run_simulation(
                SecurityScenario(arguments.scenario),
                tshark_capture=arguments.tshark_capture,
            )
        else:
            return_code = 0
        if arguments.bootstrap_scanners:
            _bootstrap_scanners()
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
            or arguments.bootstrap_scanners
        ):
            _print_status()
    except (
        DataDirectoryError,
        KillSwitchTriggered,
        MetadataExportError,
        OperationalLimitExceeded,
        ScopeValidationError,
        ImportError,
        OSError,
        RuntimeError,
        SchemaError,
        ValueError,
    ) as error:
        print(f"Execução bloqueada/falhou: {error}", file=sys.stderr)
        return 1
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
