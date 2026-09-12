"""Secret handling: env vars, ``_FILE`` indirection, and leak prevention.

Every secret-bearing setting supports a ``_FILE`` suffix so Docker/Podman secrets
work without putting values in the environment:

    DAWNPATROL_SOURCE_PIHOLE_PASSWORD_FILE=/run/secrets/pihole
"""

from __future__ import annotations

import os
from pathlib import Path


class SecretStr:
    """A string that refuses to render itself in logs, reprs, or tracebacks."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        """Explicitly unwrap. The only way to read the value."""
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return "SecretStr('***')"

    __str__ = __repr__


def read_env(name: str, default: str | None = None) -> str | None:
    """Read ``name``, falling back to the contents of ``{name}_FILE``.

    The ``_FILE`` form wins when both are set, because an explicit secrets mount
    is a stronger signal of intent than an inherited environment variable.
    """
    file_var = os.environ.get(f"{name}_FILE")
    if file_var:
        path = Path(file_var)
        if not path.is_file():
            raise FileNotFoundError(f"{name}_FILE points at {file_var!r}, which does not exist")
        return path.read_text(encoding="utf-8").strip()
    value = os.environ.get(name)
    if value is None:
        return default
    return value


def read_secret(name: str, default: str = "") -> SecretStr:
    return SecretStr(read_env(name, default) or "")


def read_bool(name: str, default: bool = False) -> bool:
    raw = read_env(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def read_int(name: str, default: int) -> int:
    raw = read_env(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def read_float(name: str, default: float) -> float:
    raw = read_env(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def read_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = read_env(name)
    if raw is None or raw.strip() == "":
        return list(default or [])
    return [part.strip() for part in raw.split(",") if part.strip()]


class SecretRegistry:
    """Tracks every secret value in play so rendered output can be scanned for leaks."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def register(self, secret: SecretStr | str | None) -> None:
        value = secret.get() if isinstance(secret, SecretStr) else secret
        # Very short values produce false positives against ordinary report text.
        if value and len(value) >= 8:
            self._values.add(value)

    def scan(self, text: str) -> list[str]:
        """Return redacted markers for any secret found in ``text``."""
        hits = []
        for value in self._values:
            if value in text:
                hits.append(f"{value[:4]}...{value[-2:]} ({len(value)} chars)")
        return hits

    def redact(self, text: str) -> str:
        for value in self._values:
            text = text.replace(value, "***REDACTED***")
        return text
