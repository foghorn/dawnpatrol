"""Provider selection."""

from __future__ import annotations

import logging

from .. import providers as providers_pkg
from ..config import AISettings
from ..errors import ConfigError
from ..registry import discover
from .base import Provider

log = logging.getLogger(__name__)


def available_providers() -> dict[str, type[Provider]]:
    return {cls.name: cls for cls in discover(providers_pkg, Provider)}


def build_provider(settings: AISettings) -> Provider:
    found = available_providers()
    cls = found.get(settings.provider)
    if cls is None:
        raise ConfigError(
            f"unknown AI provider {settings.provider!r}. Available: "
            f"{', '.join(sorted(found)) or '(none discovered)'}"
        )
    return cls(settings)
