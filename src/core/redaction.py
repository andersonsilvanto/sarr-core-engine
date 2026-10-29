"""Safe JSON serialization and credential redaction for persisted records."""

import math
import re
from collections.abc import Mapping


_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|passphrase|secret|token|credential|authorization|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|cookie|session[_-]?id)"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|credential|authorization|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_AUTH_HEADER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_COMMON_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b"
)


def sanitize_text(value: str) -> str:
    sanitized = _PRIVATE_KEY.sub("[REDACTED]", value)
    sanitized = _AUTH_HEADER.sub("[REDACTED]", sanitized)
    sanitized = _ASSIGNMENT_SECRET.sub(r"\1\2[REDACTED]", sanitized)
    sanitized = _JWT.sub("[REDACTED]", sanitized)
    return _COMMON_TOKEN.sub("[REDACTED]", sanitized)


def sanitize_json_value(value: object, *, key: str = "") -> object:
    if key and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON persistence does not accept non-finite numbers.")
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        for nested_key, nested_value in value.items():
            if not isinstance(nested_key, str):
                raise TypeError("Persisted JSON object keys must be strings.")
            sanitized[nested_key] = sanitize_json_value(
                nested_value, key=nested_key
            )
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize_json_value(item) for item in value]
    raise TypeError(f"Unsupported persisted JSON value: {type(value).__name__}.")
