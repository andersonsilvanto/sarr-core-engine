"""Validação fail-closed de escopos de execução locais."""

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Callable, Iterable

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from core.kill_switch import KillSwitch


class ScopeValidationError(ValueError):
    """Raised when a scope file is absent, invalid, expired, or insufficient."""


@dataclass(frozen=True)
class ScopeLimits:
    max_duration_seconds: float
    max_rate_per_second: float
    max_concurrency: int
    max_volume_bytes: int
    measurement_window_seconds: int


@dataclass(frozen=True)
class ValidatedScope:
    engagement_id: str
    environment: str
    mode: str
    valid_from_utc: datetime
    valid_until_utc: datetime
    allowed_targets: frozenset[str]
    allowed_modules: frozenset[str]
    limits: ScopeLimits
    scope_sha256: str


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScopeValidationError(f"Chave JSON duplicada: {key}.")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise ScopeValidationError(f"Constante numérica JSON inválida: {value}.")


def _parse_utc_timestamp(value: str, field: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ScopeValidationError(f"{field} não é um timestamp válido.") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ScopeValidationError(f"{field} deve estar explicitamente em UTC.")
    return parsed.astimezone(timezone.utc)


class ScopeValidator:
    def __init__(
        self,
        schema_path: str | Path | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        kill_switch: KillSwitch | None = None,
    ) -> None:
        source_schema = (
            Path(__file__).resolve().parents[2] / "schemas" / "scope.schema.json"
        )
        bundle_root = Path(getattr(sys, "_MEIPASS", sys.prefix))
        bundled_schema = bundle_root / "schemas" / "scope.schema.json"
        installed_schema = Path(sys.prefix) / "schemas" / "scope.schema.json"
        self._schema_path = (
            Path(schema_path)
            if schema_path
            else source_schema
            if source_schema.is_file()
            else bundled_schema
            if bundled_schema.is_file()
            else installed_schema
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._kill_switch = kill_switch
        self._validator = self._load_schema()

    def _load_schema(self) -> Draft202012Validator:
        try:
            schema = json.loads(
                self._schema_path.read_text(encoding="utf-8"),
                parse_constant=_reject_nonfinite_constant,
            )
        except OSError as error:
            raise ScopeValidationError(
                f"Schema de escopo indisponível: {self._schema_path}."
            ) from error
        except (json.JSONDecodeError, ScopeValidationError) as error:
            raise ScopeValidationError(
                f"Schema JSON inválido: {self._schema_path}."
            ) from error
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            raise ScopeValidationError(
                f"Schema de escopo inválido: {self._schema_path}."
            ) from error
        return Draft202012Validator(schema, format_checker=FormatChecker())

    def validate(
        self,
        scope_path: str | Path,
        *,
        engagement_id: str,
        environment: str,
        mode: str,
        targets: Iterable[str],
        modules: Iterable[str],
    ) -> ValidatedScope:
        if self._kill_switch is not None:
            self._kill_switch.assert_clear()
        path = Path(scope_path)
        try:
            scope_bytes = path.read_bytes()
            data = json.loads(
                scope_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
        except OSError as error:
            raise ScopeValidationError(f"Arquivo de escopo ausente ou ilegível: {path}.") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScopeValidationError(f"Arquivo de escopo não contém JSON válido: {path}.") from error

        errors = sorted(
            self._validator.iter_errors(data),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            details = "; ".join(
                f"{'.'.join(str(part) for part in error.absolute_path) or '<raiz>'}: "
                f"{error.message}"
                for error in errors
            )
            raise ScopeValidationError(f"Escopo não corresponde ao schema: {details}")

        valid_from = _parse_utc_timestamp(data["valid_from_utc"], "valid_from_utc")
        valid_until = _parse_utc_timestamp(data["valid_until_utc"], "valid_until_utc")
        if valid_until <= valid_from:
            raise ScopeValidationError("valid_until_utc deve ser posterior a valid_from_utc.")
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            raise ValueError("clock deve retornar um datetime timezone-aware em UTC.")
        now = now.astimezone(timezone.utc)
        if now < valid_from or now > valid_until:
            raise ScopeValidationError("Escopo ainda não é válido ou está expirado.")

        expected = {
            "engagement_id": engagement_id,
            "environment": environment,
            "mode": mode,
        }
        for field, value in expected.items():
            if not isinstance(value, str) or data[field] != value:
                raise ScopeValidationError(f"{field} do escopo não corresponde à execução.")

        requested_targets = self._unique_values(targets, "targets")
        requested_modules = self._unique_values(modules, "modules")
        disallowed_targets = requested_targets - set(data["allowed_targets"])
        if disallowed_targets:
            raise ScopeValidationError(
                "Alvos fora da allowlist estrita: "
                + ", ".join(sorted(disallowed_targets))
            )
        disallowed_modules = requested_modules - set(data["allowed_modules"])
        if disallowed_modules:
            raise ScopeValidationError(
                "Módulos não autorizados: " + ", ".join(sorted(disallowed_modules))
            )

        limits = data["limits"]
        return ValidatedScope(
            engagement_id=data["engagement_id"],
            environment=data["environment"],
            mode=data["mode"],
            valid_from_utc=valid_from,
            valid_until_utc=valid_until,
            allowed_targets=frozenset(data["allowed_targets"]),
            allowed_modules=frozenset(data["allowed_modules"]),
            limits=ScopeLimits(
                max_duration_seconds=limits["max_duration_seconds"],
                max_rate_per_second=limits["max_rate_per_second"],
                max_concurrency=limits["max_concurrency"],
                max_volume_bytes=limits["max_volume_bytes"],
                measurement_window_seconds=limits["measurement_window_seconds"],
            ),
            scope_sha256=hashlib.sha256(scope_bytes).hexdigest(),
        )

    @staticmethod
    def _unique_values(values: Iterable[str], field: str) -> set[str]:
        if isinstance(values, (str, bytes)):
            raise ScopeValidationError(f"{field} deve ser uma coleção de valores.")
        try:
            entries = tuple(values)
        except TypeError as error:
            raise ScopeValidationError(f"{field} deve ser iterável.") from error
        if not entries:
            raise ScopeValidationError(f"{field} não pode ser vazio.")
        if any(not isinstance(value, str) or not value for value in entries):
            raise ScopeValidationError(f"{field} contém um valor inválido.")
        if len(set(entries)) != len(entries):
            raise ScopeValidationError(f"{field} contém valores duplicados.")
        return set(entries)
