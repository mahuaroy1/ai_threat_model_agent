"""Detection and redaction of secrets and personal data.

The scanner never writes a full secret value to a report or log: every
snippet passes through :func:`redact` before it leaves the analyzers.
"""

from __future__ import annotations

import re

# Well-known credential formats. Order matters only for readability.
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"sk-(?:proj-|svcacct-|admin-|ant-)?[A-Za-z0-9_\-]{20,}",  # OpenAI / Anthropic
        r"AKIA[0-9A-Z]{16}",  # AWS access key id
        r"gh[pousr]_[A-Za-z0-9]{36,}",  # GitHub token
        r"github_pat_[A-Za-z0-9_]{22,}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",  # Slack
        r"AIza[0-9A-Za-z_\-]{35}",  # Google API key
        r"lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,}",  # LangSmith
        r"hf_[A-Za-z0-9]{30,}",  # Hugging Face
        r"tvly-[A-Za-z0-9_\-]{20,}",  # Tavily
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        r"\b[a-z][a-z0-9+]*://[^\s:/@'\"]+:[^\s@/'\"]{3,}@",  # URL with embedded password
    )
)

_SECRET_NAME_RE = re.compile(
    r"(^|_)(api_?key|secret|secret_key|password|passwd|pwd|token|access_token|auth_token|"
    r"bearer|credentials?|private_key|access_key|client_secret|connection_string|conn_str)(_|$)"
)
_NON_SECRET_NAME_RE = re.compile(
    r"(^|_)(max|num|total)_tokens?(_|$)|(^|_)token_(count|limit|usage|len|length|budget|ids?|type|counter)(_|$)"
)
_PII_NAME_RE = re.compile(
    r"(^|_)(ssn|dob|cvv|iban|passport|salary|diagnosis|patient|email|phone|"
    r"social_security|credit_card|card_number|date_of_birth|driver_licen[cs]e|national_id|"
    r"tax_id|account_number|routing_number|medical_record|health_record|home_address)(_|$)"
)
_PLACEHOLDER_RE = re.compile(
    r"^(|x+|\*+|\.+|changeme|change_me|placeholder|dummy|example|test|none|null|todo|"
    r"your[\w\- ]*|<.*>|\$\{.*\}|\$[A-Z_]+|\{\{.*\}\}|.*xxxx.*|.*example.*|.*\.\.\..*)$",
    re.IGNORECASE,
)
_ASSIGNMENT_VALUE_RE = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]+)(?P<sep>["']?\s*[:=]\s*["']?)(?P<value>[^"'\s,#}]+)"""
)


def normalize_identifier(name: str) -> str:
    """Convert ``camelCase`` / ``kebab-case`` / ``dotted.names`` to ``snake_case``."""
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").lower()


def is_secret_name(name: str) -> bool:
    """Return True if an identifier or config key looks like it holds a credential."""
    normalized = normalize_identifier(name)
    return bool(_SECRET_NAME_RE.search(normalized)) and not _NON_SECRET_NAME_RE.search(normalized)


def is_pii_name(name: str) -> bool:
    """Return True if an identifier looks like it holds personal data."""
    return bool(_PII_NAME_RE.search(normalize_identifier(name)))


def is_placeholder(value: str) -> bool:
    """Return True for obviously fake or templated values such as ``<your-key>``."""
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def looks_like_secret_value(value: str) -> bool:
    """Heuristic for literals assigned to secret-named variables."""
    value = value.strip()
    return len(value) >= 8 and " " not in value and not is_placeholder(value)


def find_token(text: str) -> str | None:
    """Return the first well-known credential found in ``text``, if any."""
    for pattern in TOKEN_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def mask(value: str) -> str:
    """Keep a short prefix so a reviewer can identify the credential type."""
    return f"{value[:4]}…[REDACTED]" if len(value) > 4 else "[REDACTED]"


def redact(text: str) -> str:
    """Mask known credential formats and values of secret-named assignments."""
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda match: mask(match.group(0)), text)

    def _mask_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if is_secret_name(match.group("key")) and looks_like_secret_value(value) and "REDACTED" not in value:
            return f"{match.group('key')}{match.group('sep')}{mask(value)}"
        return match.group(0)

    return _ASSIGNMENT_VALUE_RE.sub(_mask_assignment, text)
