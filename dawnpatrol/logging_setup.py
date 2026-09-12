"""Logging configuration. Structured enough to grep, plain enough to read."""

from __future__ import annotations

import logging
import sys

from .secrets import SecretRegistry


class RedactingFilter(logging.Filter):
    """Last line of defence: no configured secret reaches a log handler."""

    def __init__(self, registry: SecretRegistry) -> None:
        super().__init__()
        self._registry = registry

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        redacted = self._registry.redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def configure(level: str = "INFO", registry: SecretRegistry | None = None) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)-28s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    if registry is not None:
        handler.addFilter(RedactingFilter(registry))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Third-party noise that is never useful at our level.
    for noisy in ("httpx", "httpcore", "urllib3", "sqlalchemy.engine.Engine", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
