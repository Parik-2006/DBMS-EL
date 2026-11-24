"""
Secret and sensitive-data redaction.

Used for (a) application logs, (b) error strings returned by external API
clients, and (c) forensic documents before they are written to MongoDB.
"""

import logging
import os
import re
from typing import Any

REDACTED = '[REDACTED]'

SENSITIVE_HEADER_NAMES = frozenset({
    'set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate',
    'proxy-authenticate', 'x-api-key', 'x-goog-api-key', 'auth-key', 'key', 'x-auth-token',
    'x-csrftoken', 'x-csrf-token', 'x-amz-security-token',
})

# Environment variables whose *values* must never appear in logs or documents.
SECRET_ENV_VARS = (
    'SECRET_KEY', 'MYSQL_PASSWORD', 'MYSQL_ADMIN_PASSWORD', 'MONGODB_URI',
    'GEMINI_API_KEY', 'OPENROUTER_API_KEY', 'THREATFOX_API_KEY', 'URLHAUS_API_KEY',
    'ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY', 'ALIENVAULT_API_KEY', 'FALLBACK_SERVICE_TOKEN',
)

_PATTERNS = [
    # key=..., api_key=..., token=..., password=... in URLs / query strings / text
    (re.compile(r'(?i)((?:^|[?&;\s"\'])(?:key|api[_-]?key|access[_-]?token|token|auth|password|passwd|pwd|secret)=)[^&\s"\'<>]+'),
     r'\1' + REDACTED),
    (re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}'), r'\1 ' + REDACTED),
    (re.compile(r'(?i)((?:auth-key|x-goog-api-key|x-api-key|authorization)\s*[:=]\s*)[^\s,;"\']+'), r'\1' + REDACTED),
    (re.compile(r'(mongodb(?:\+srv)?://)[^:/@\s]+:[^@\s]+@'), r'\1' + REDACTED + '@'),
    (re.compile(r'(mysql://)[^:/@\s]+:[^@\s]+@'), r'\1' + REDACTED + '@'),
    (re.compile(r'\bAIza[0-9A-Za-z_-]{20,}\b'), REDACTED),           # Google API keys
    (re.compile(r'\bsk-or-[0-9A-Za-z_-]{16,}\b'), REDACTED),          # OpenRouter keys
]


def _secret_values():
    values = []
    for name in SECRET_ENV_VARS:
        val = os.environ.get(name)
        if val and len(val) >= 6:
            values.append(val)
    return values


def redact_text(text: Any) -> Any:
    """Redact secrets from a string (non-strings are returned unchanged)."""
    if not isinstance(text, str) or not text:
        return text
    for value in _secret_values():
        if value in text:
            text = text.replace(value, REDACTED)
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_headers(headers: Any) -> Any:
    if not isinstance(headers, dict):
        return headers
    clean = {}
    for k, v in headers.items():
        if str(k).lower() in SENSITIVE_HEADER_NAMES:
            clean[k] = REDACTED
        else:
            clean[k] = redact_text(v) if isinstance(v, str) else v
    return clean


_HEADER_CONTAINER_KEYS = frozenset({'response_headers', 'headers', 'request_headers'})


def redact_document(obj: Any, _depth: int = 0) -> Any:
    """Deep-redact a forensic document (dict/list tree) before persistence."""
    if _depth > 40:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = str(k)
            if key.lower() in _HEADER_CONTAINER_KEYS and isinstance(v, dict):
                out[k] = redact_headers(v)
            elif key.lower() in SENSITIVE_HEADER_NAMES and isinstance(v, str):
                out[k] = REDACTED
            else:
                out[k] = redact_document(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_document(v, _depth + 1) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_document(v, _depth + 1) for v in obj)
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def safe_exception_message(exc: BaseException, limit: int = 200) -> str:
    """Exception summary safe for logs / persisted error fields."""
    return redact_text(f"{type(exc).__name__}: {exc}")[:limit]


class RedactingFilter(logging.Filter):
    """Logging filter that redacts secrets from every record's message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = redact_text(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True
