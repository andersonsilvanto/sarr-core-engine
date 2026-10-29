"""Structured, sanitized audit reports for completed or interrupted runs."""

import csv
import html
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Mapping
from uuid import UUID, uuid4

from core.orchestrator import CoreOrchestrator
from core.redaction import sanitize_json_value, sanitize_text
from core.state_machine import RunState
from sarr_core import __version__


_REQUIRED_REPORT_FIELDS = (
    "report_id",
    "system",
    "operator",
    "scope",
    "execution",
    "metrics",
    "findings",
    "kill_switch",
    "stop_reason",
    "limitations",
    "recommendations",
)


class ReportGenerationError(RuntimeError):
    """Raised when a complete audit report cannot be built or exported."""


def _isoformat(value: object) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    if not callable(isoformat):
        raise TypeError("Report timestamps must be datetime values.")
    return isoformat().replace("+00:00", "Z")


def _markdown_text(value: object) -> str:
    safe = html.escape(str(value), quote=False)
    for character in "\\`*_{}[]()#+-.!|>":
        safe = safe.replace(character, f"\\{character}")
    return safe.replace("\r", " ").replace("\n", " ")


def _markdown_code(value: object) -> str:
    safe = html.escape(str(value), quote=False).replace("`", "&#96;")
    return safe.replace("\r", " ").replace("\n", " ")


def _aggregate_metrics(
    metrics: tuple[tuple[str, float, str], ...]
) -> dict[str, object]:
    grouped: dict[tuple[str, str], list[float]] = {}
    for name, value, unit in metrics:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        grouped.setdefault((name, unit), []).append(float(value))

    aggregates: dict[str, object] = {}
    for (name, unit), values in sorted(grouped.items()):
        if not all(math.isfinite(value) for value in values):
            raise ReportGenerationError(
                f"Non-finite value found for metric {name!r}."
            )
        key = name if name not in aggregates else f"{name} ({unit})"
        aggregates[key] = {
            "unit": unit,
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / len(values),
        }
    return aggregates


class AuditReportService:
    def __init__(
        self,
        orchestrator: CoreOrchestrator,
        *,
        system_name: str = "SARR-Core Engine",
        system_version: str = __version__,
    ) -> None:
        if not isinstance(orchestrator, CoreOrchestrator):
            raise TypeError("orchestrator must be a CoreOrchestrator.")
        if not isinstance(system_name, str) or not system_name.strip():
            raise ValueError("system_name must be a non-empty string.")
        if not isinstance(system_version, str) or not system_version.strip():
            raise ValueError("system_version must be a non-empty string.")
        self._orchestrator = orchestrator
        self._system_name = sanitize_text(system_name.strip())
        self._system_version = sanitize_text(system_version.strip())

    def build_report(self, run_id: UUID, *, operator: str) -> dict[str, object]:
        if not isinstance(run_id, UUID):
            raise TypeError("run_id must be a UUID.")
        if not isinstance(operator, str) or not operator.strip():
            raise ValueError("operator must be a non-empty string.")

        try:
            context = self._orchestrator.get_run_context(run_id)
            scope = self._orchestrator.get_validated_scope(run_id)
            started_at, ended_at = self._orchestrator.get_run_timestamps(run_id)
            state = self._orchestrator.get_state(run_id)
        except KeyError as error:
            raise ReportGenerationError(
                "A run and a validated scope are required to build a report."
            ) from error

        events = tuple(
            event
            for event in self._orchestrator.events.history
            if event.run_id == run_id
        )
        persistence = self._orchestrator.persistence
        if persistence is not None:
            metric_records = persistence.metrics.list_for_run(run_id)
            metric_values = tuple(
                (record.name, record.value, record.unit)
                for record in metric_records
            )
            finding_records = persistence.findings.list_for_run(run_id)
            findings: list[dict[str, object]] = [
                {
                    "finding_id": str(record.finding_id),
                    "created_at_utc": record.created_at_utc,
                    "severity": record.severity,
                    "title": record.title,
                    "description": record.description,
                    "evidence": dict(record.details),
                }
                for record in finding_records
            ]
        else:
            metric_values_list: list[tuple[str, float, str]] = []
            findings = []
            for event in events:
                if event.name == "metric.sample":
                    payload = event.payload
                    telemetry_fields = (
                        ("cpu_percent", "percent"),
                        ("ram_percent", "percent"),
                        ("rtt_ms", "ms"),
                        ("drop_rate", "ratio"),
                    )
                    found_telemetry_value = False
                    for field_name, unit in telemetry_fields:
                        value = payload.get(field_name)
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            metric_values_list.append((field_name, float(value), unit))
                            found_telemetry_value = True
                    metric_name = payload.get("metric")
                    metric_value = payload.get("value")
                    metric_unit = payload.get("unit")
                    if (
                        not found_telemetry_value
                        and isinstance(metric_name, str)
                        and isinstance(metric_value, (int, float))
                        and not isinstance(metric_value, bool)
                        and isinstance(metric_unit, str)
                    ):
                        metric_values_list.append(
                            (metric_name, float(metric_value), metric_unit)
                        )
                if event.name == "finding.created":
                    payload = dict(event.payload)
                    findings.append(
                        {
                            "finding_id": payload.get("finding_id", str(event.event_id)),
                            "created_at_utc": _isoformat(event.timestamp_utc),
                            "severity": payload.get("severity", "unspecified"),
                            "title": payload.get("title", ""),
                            "description": payload.get("description", ""),
                            "evidence": {
                                key: value
                                for key, value in payload.items()
                                if key
                                not in {
                                    "finding_id",
                                    "severity",
                                    "title",
                                    "description",
                                }
                            },
                        }
                    )
            metric_values = tuple(metric_values_list)

        executed_modules = sorted(
            {
                str(event.payload["module"])
                for event in events
                if event.name == "module.executed"
                and isinstance(event.payload.get("module"), str)
            }
        )
        safety_events = [
            {
                "timestamp_utc": _isoformat(event.timestamp_utc),
                "reason_code": event.payload.get("reason_code", "unknown"),
            }
            for event in events
            if event.name == "safety.triggered"
        ]
        stop_events = [
            event
            for event in events
            if event.name == "run.stopped"
        ]
        stop_reason = (
            stop_events[-1].payload.get("reason_code")
            if stop_events
            else safety_events[-1]["reason_code"]
            if safety_events
            else "completed"
            if state is RunState.COMPLETED
            else "not_recorded"
        )

        report: dict[str, object] = {
            "report_id": str(uuid4()),
            "system": {
                "name": self._system_name,
                "version": self._system_version,
                "run_id": str(run_id),
            },
            "operator": sanitize_text(operator.strip()),
            "scope": {
                "engagement_id": scope.engagement_id,
                "environment": scope.environment,
                "sha256": scope.scope_sha256,
                "valid_from_utc": _isoformat(scope.valid_from_utc),
                "valid_until_utc": _isoformat(scope.valid_until_utc),
            },
            "execution": {
                "mode": context.mode,
                "state": state.value,
                "modules_executed": executed_modules,
                "started_at_utc": _isoformat(started_at),
                "ended_at_utc": _isoformat(ended_at),
            },
            "metrics": _aggregate_metrics(metric_values),
            "findings": findings,
            "kill_switch": {
                "triggered": bool(safety_events),
                "events": safety_events,
            },
            "stop_reason": stop_reason,
            "limitations": [
                "O relatório inclui apenas dados registrados para esta execução.",
                "Módulos executados são identificados por eventos module.executed.",
                "Métricas agregadas incluem somente valores numéricos persistidos.",
            ],
            "recommendations": [
                "Mantenha o escopo restrito aos alvos e módulos estritamente necessários.",
                "Investigue achados e eventos do kill-switch antes de qualquer nova execução.",
                "Revise limites operacionais e validade do escopo antes de autorizar outra execução.",
            ],
        }
        return self.validate_report(report)

    @staticmethod
    def validate_report(report: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(report, Mapping):
            raise TypeError("report must be a mapping.")
        missing = [field for field in _REQUIRED_REPORT_FIELDS if field not in report]
        if missing:
            raise ReportGenerationError(
                "Required report fields are missing: " + ", ".join(missing)
            )
        sanitized = sanitize_json_value(report)
        if not isinstance(sanitized, dict):
            raise ReportGenerationError("Sanitized report must be a JSON object.")
        expected_shapes = {
            "system": ("name", "version", "run_id"),
            "scope": (
                "engagement_id",
                "environment",
                "sha256",
                "valid_from_utc",
                "valid_until_utc",
            ),
            "execution": (
                "mode",
                "state",
                "modules_executed",
                "started_at_utc",
                "ended_at_utc",
            ),
            "kill_switch": ("triggered", "events"),
        }
        for field, required_keys in expected_shapes.items():
            section = sanitized[field]
            if not isinstance(section, dict):
                raise ReportGenerationError(
                    f"Report section {field!r} must be an object."
                )
            absent = [key for key in required_keys if key not in section]
            if absent:
                raise ReportGenerationError(
                    f"Report section {field!r} is missing: "
                    + ", ".join(absent)
                    + "."
                )
        for field in ("report_id", "operator", "stop_reason"):
            if not isinstance(sanitized[field], str) or not sanitized[field].strip():
                raise ReportGenerationError(
                    f"Report field {field!r} must be a non-empty string."
                )
        if not isinstance(sanitized["system"]["name"], str) or not isinstance(
            sanitized["system"]["version"], str
        ):
            raise ReportGenerationError("System name and version must be strings.")
        if not isinstance(sanitized["scope"]["sha256"], str) or len(
            sanitized["scope"]["sha256"]
        ) != 64:
            raise ReportGenerationError("Scope sha256 must be a 64-character digest.")
        if any(
            character not in "0123456789abcdef"
            for character in sanitized["scope"]["sha256"]
        ):
            raise ReportGenerationError("Scope sha256 must be lowercase hexadecimal.")
        if not isinstance(sanitized["execution"]["modules_executed"], list):
            raise ReportGenerationError("Executed modules must be an array.")
        if not isinstance(sanitized["metrics"], dict):
            raise ReportGenerationError("Report metrics must be an object.")
        if not isinstance(sanitized["findings"], list):
            raise ReportGenerationError("Report findings must be an array.")
        if not isinstance(sanitized["kill_switch"]["triggered"], bool) or not isinstance(
            sanitized["kill_switch"]["events"], list
        ):
            raise ReportGenerationError("Kill-switch status or events are invalid.")
        if not isinstance(sanitized["limitations"], list):
            raise ReportGenerationError("Report limitations must be an array.")
        if not isinstance(sanitized["recommendations"], list):
            raise ReportGenerationError("Report recommendations must be an array.")
        try:
            json.dumps(
                sanitized,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ReportGenerationError(
                "Report contains values that cannot be represented as safe JSON."
            ) from error
        return sanitized

    @classmethod
    def export_json(
        cls, report: Mapping[str, object], destination: str | Path
    ) -> Path:
        validated = cls.validate_report(report)
        content = (
            json.dumps(
                validated,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        return cls._atomic_write(destination, content)

    @classmethod
    def export_markdown(
        cls, report: Mapping[str, object], destination: str | Path
    ) -> Path:
        validated = cls.validate_report(report)
        system = validated["system"]
        execution = validated["execution"]
        scope = validated["scope"]
        kill_switch = validated["kill_switch"]
        if not (
            isinstance(system, dict)
            and isinstance(execution, dict)
            and isinstance(scope, dict)
            and isinstance(kill_switch, dict)
        ):
            raise ReportGenerationError("Report sections are invalid for Markdown export.")

        lines = [
            "# Relatório Executivo de Auditoria",
            "",
            f"- Sistema: {_markdown_text(system['name'])} "
            f"{_markdown_text(system['version'])}",
            f"- Execução: `{_markdown_code(system['run_id'])}`",
            f"- Relatório: `{_markdown_code(validated['report_id'])}`",
            f"- Operador: {_markdown_text(validated['operator'])}",
            f"- Ambiente: {_markdown_text(scope['environment'])}",
            f"- Estado: **{_markdown_text(execution['state'])}**",
            f"- Kill-switch: **{'acionado' if kill_switch['triggered'] else 'inativo'}**",
            f"- Motivo de parada: `{_markdown_code(validated['stop_reason'])}`",
            "",
            "## Achados",
            "",
        ]
        findings = validated["findings"]
        if not findings:
            lines.append("Nenhum finding registrado.")
        else:
            for index, finding in enumerate(findings, start=1):
                if not isinstance(finding, dict):
                    raise ReportGenerationError("Finding entries must be objects.")
                evidence = finding.get("evidence", {})
                if not isinstance(evidence, dict):
                    raise ReportGenerationError("Finding evidence must be an object.")
                rendered_evidence = json.dumps(
                    evidence,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                )
                lines.extend(
                    (
                        f"### {index}. [{_markdown_code(finding.get('severity', 'unspecified'))}] "
                        f"`{_markdown_code(finding.get('title', ''))}`",
                        "",
                        _markdown_text(finding.get("description", "")),
                        "",
                        f"- MITRE ATT&CK: `{_markdown_code(evidence.get('mitre_id', 'N/A'))}`",
                        "- Evidência: `" + _markdown_code(rendered_evidence) + "`",
                        "",
                    )
                )

        lines.extend(("# Recomendações", ""))
        recommendations = validated["recommendations"]
        if not isinstance(recommendations, list):
            raise ReportGenerationError("Report recommendations must be an array.")
        lines.extend(f"- {_markdown_text(item)}" for item in recommendations)
        lines.extend(("", "## Limitações", ""))
        limitations = validated["limitations"]
        if not isinstance(limitations, list):
            raise ReportGenerationError("Report limitations must be an array.")
        lines.extend(f"- {_markdown_text(item)}" for item in limitations)
        lines.append("")
        return cls._atomic_write(
            destination,
            "\n".join(lines).encode("utf-8"),
        )

    @classmethod
    def export_csv(
        cls, report: Mapping[str, object], destination: str | Path
    ) -> Path:
        validated = cls.validate_report(report)
        rows: list[tuple[str, str, str]] = []
        for section, value in validated.items():
            if isinstance(value, Mapping):
                if not value:
                    rows.append((section, "", "{}"))
                rows.extend(
                    (
                        section,
                        str(item_name),
                        json.dumps(
                            item_value,
                            ensure_ascii=False,
                            sort_keys=True,
                            allow_nan=False,
                        ),
                    )
                    for item_name, item_value in value.items()
                )
            elif isinstance(value, list):
                if not value:
                    rows.append((section, "", "[]"))
                rows.extend(
                    (
                        section,
                        str(index),
                        json.dumps(
                            item_value,
                            ensure_ascii=False,
                            sort_keys=True,
                            allow_nan=False,
                        ),
                    )
                    for index, item_value in enumerate(value)
                )
            else:
                rows.append(
                    (
                        section,
                        "",
                        json.dumps(value, ensure_ascii=False, allow_nan=False),
                    )
                )

        import io

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("section", "item", "data_json"))
        writer.writerows(rows)
        return cls._atomic_write(
            destination,
            output.getvalue().encode("utf-8"),
        )

    @staticmethod
    def _atomic_write(destination: str | Path, content: bytes) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as output:
                temporary_path = Path(output.name)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
