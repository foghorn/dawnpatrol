"""Source plugin contract.

A source fetches raw records from one telemetry system and normalizes them into
:class:`~dawnpatrol.models.Event`. It does not analyze, and it does not decide
whether it is healthy - it reports facts and runs probes on request.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from ..context import RunContext
from ..models import CollectionResult, EventKind, Probe, Window
from ..profile import Profile

log = logging.getLogger(__name__)


class Source(ABC):
    #: Unique plugin name; also the ``Event.source`` value.
    name: str = ""
    #: Event kinds this source can emit.
    kinds: frozenset[EventKind] = frozenset()
    #: Env vars that must all be present for this source to auto-enable.
    requires_env: frozenset[str] = frozenset()
    #: Hard retention ceiling. The framework clamps and labels rather than
    #: reporting a shortfall, because a known limit is not a collection failure.
    max_window_hours: int | None = None
    #: Volume floor below which a result is a collection defect until proven otherwise.
    min_expected_records: int = 0

    def __init__(self) -> None:
        self.profile: Profile = Profile()
        self.options: dict[str, Any] = {}

    def configure(self, profile: Profile) -> None:
        self.profile = profile
        self.options = (profile.source_hints or {}).get(self.name, {}) or {}

    @abstractmethod
    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        """Fetch and normalize. Raise CollectionError only for genuine failures.

        Returning zero events is a legitimate outcome and must not raise - the
        framework will call :meth:`self_test` to work out what zero means.
        """

    def self_test(self, ctx: RunContext) -> list[Probe]:
        """Differential probes, run automatically when collection returns nothing.

        The point is to distinguish "my query was malformed" from "the feed is
        dead". Sources that can cheaply prove the difference should override.
        """
        return []

    def extra_health_notes(self, result: CollectionResult) -> list[str]:
        """Source-specific caveats appended to the health record."""
        return []

    def effective_window(self, window: Window) -> Window:
        return window.clamp_hours(self.max_window_hours)

    def assign_zones(self, **kwargs: Any) -> dict[str, Any]:
        """Helper for normalizers: resolve src/dst zones from the profile."""
        out = dict(kwargs)
        if "src_ip" in out:
            out["src_zone"] = self.profile.zone_of(out.get("src_ip"))
        if "dst_ip" in out:
            out["dst_zone"] = self.profile.zone_of(out.get("dst_ip"))
        if "client_ip" in out and not out.get("src_zone"):
            out["src_zone"] = self.profile.zone_of(out.get("client_ip"))
        return out

    def __repr__(self) -> str:
        return f"<Source {self.name}>"
