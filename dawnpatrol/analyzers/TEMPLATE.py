"""Template for a new analyzer. Copy, rename, edit. Never loaded by the registry.

Analyzers are pure functions over the event store. No network, no model calls.
That is what makes them testable against fixtures and free to iterate on.

Emit two things:
  * Metric - a number that belongs in the report verbatim.
  * Signal - a candidate finding with the evidence that justifies it. Every
    Finding the model produces must cite at least one Signal id, so anything
    you want the model to be *able* to report must originate here.
"""

from __future__ import annotations

from ..models import AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from .base import Analyzer
from .baseline import Baseline


class TemplateAnalyzer(Analyzer):
    name = "template"
    requires_kinds = frozenset({EventKind.FIREWALL})
    order = 100

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)

        total = q.count(kind=EventKind.FIREWALL)
        result.metrics.append(
            Metric(key="template.total", value=total, section="perimeter",
                   label="Example total")
        )

        if total > 10_000:
            result.signals.append(
                Signal(
                    id=f"template.high_volume.{total}",
                    analyzer=self.name,
                    title="Unusually high firewall volume",
                    taxonomy="volume.spike",
                    severity_hint=Severity.LOW,
                    confidence=0.6,
                    entities=[Entity(type=EntityType.HOST, value="perimeter")],
                    evidence={"total": total, "prior": baseline.prior("template.total")},
                    narrative_hint="Volume alone is rarely a finding; check attribution.",
                )
            )
        return result
