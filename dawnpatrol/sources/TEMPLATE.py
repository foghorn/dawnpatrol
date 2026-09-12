"""Template for a new log source. Copy, rename, edit. Never loaded by the registry.

Checklist for a new source:
  1. Pick a unique ``name`` - it becomes ``Event.source`` and the env prefix.
  2. Declare ``requires_env``; the source auto-enables when those are all set.
  3. Set ``max_window_hours`` if the upstream has a retention ceiling. The
     framework clamps and labels it as a known limit, not a shortfall.
  4. Normalize into the common Event model so cross-source correlation works.
  5. Implement ``self_test`` if you can cheaply prove "empty result" apart from
     "dead feed". This is what stops a malformed query becoming a false outage.
"""

from __future__ import annotations

from ..context import RunContext
from ..models import CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_env
from .base import Source


class TemplateSource(Source):
    name = "template"
    kinds = frozenset({EventKind.OTHER})
    requires_env = frozenset({"DAWNPATROL_SOURCE_TEMPLATE_URL"})
    max_window_hours = None
    min_expected_records = 0

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        result = CollectionResult(
            source=self.name,
            window=self.effective_window(window),
            requested_window=window,
        )
        base_url = read_env("DAWNPATROL_SOURCE_TEMPLATE_URL", "")
        if not base_url:
            result.errors.append("no URL configured")
            return result

        # ... fetch records, paginating to completion ...
        records: list[dict] = []
        result.pages = 1
        result.reported_total = len(records)

        for rec in records:
            result.events.append(
                Event(
                    ts=rec["timestamp"],          # must be tz-aware UTC
                    source=self.name,
                    kind=EventKind.OTHER,
                    dedup_key=Event.make_dedup_key(self.name, rec.get("id")),
                    message=rec.get("message"),
                    **self.assign_zones(src_ip=rec.get("src")),
                )
            )
        return result

    def self_test(self, ctx: RunContext) -> list[Probe]:
        return [
            Probe(name="auth", request="GET /health", ok=True, status=200,
                  detail="replace with a real unfiltered probe"),
        ]
