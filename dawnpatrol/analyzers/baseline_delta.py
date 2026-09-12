"""Day-over-day and multi-day trend comparison.

Runs last so it can compare this run's metrics against history. A metric that
moved by an order of magnitude is far more likely a collection defect than a
real event, so that case is flagged as a data-quality question rather than a
security finding.
"""

from __future__ import annotations

from ..models import AnalyzerResult, Entity, EntityType, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from .base import Analyzer
from .baseline import Baseline

WATCHED = (
    ("fw.drops", "firewall DROPs"),
    ("fw.unique_sources", "unique external sources"),
    ("dns.total", "DNS queries"),
    ("dns.blocked", "blocked DNS queries"),
    ("dns.unique_domains", "unique domains"),
    ("beacon.candidates", "beacon candidates"),
)
ORDER_OF_MAGNITUDE = 10.0
MATERIAL_CHANGE_PCT = 60.0


class BaselineDeltaAnalyzer(Analyzer):
    name = "baseline_delta"
    order = 900

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        if not baseline.has_baseline():
            r.notes.append("no prior run to compare against - first run, no baseline")
            r.metrics.append(Metric(key="trend.baseline_available", value=0,
                                    section="trend", label="Baseline available"))
            return r

        r.metrics.append(Metric(key="trend.baseline_available", value=1,
                                section="trend", label="Baseline available"))
        prior = baseline.prior_metrics

        # Current values are not yet persisted, so read them from this run's
        # events rather than from the metrics table.
        current = {
            "fw.drops": q.count(kind="firewall", action="drop"),
            "fw.unique_sources": q.distinct_count("src_ip", kind="firewall"),
            "dns.total": q.count(kind="dns"),
            "dns.blocked": q.count(kind="dns", blocked=True),
            "dns.unique_domains": q.distinct_count("domain", kind="dns"),
        }

        for key, label in WATCHED:
            before = prior.get(key)
            now = current.get(key)
            if before is None or now is None or before <= 0:
                continue
            ratio = now / before
            change_pct = (now - before) / before * 100.0
            r.metrics.append(Metric(
                key=f"trend.{key}.change_pct", value=round(change_pct, 1),
                section="trend", unit="%", label=f"Change in {label}",
            ))

            if ratio >= ORDER_OF_MAGNITUDE or (ratio <= 1 / ORDER_OF_MAGNITUDE and now >= 0):
                r.signals.append(Signal(
                    id=f"trend.anomaly.{key}",
                    analyzer=self.name,
                    title=f"{label} moved by more than an order of magnitude",
                    taxonomy="dataquality.magnitude_shift",
                    severity_hint=Severity.LOW,
                    confidence=0.5,
                    entities=[Entity(type=EntityType.HOST, value="pipeline")],
                    evidence={
                        "metric": key, "prior": before, "current": now,
                        "ratio": round(ratio, 3),
                    },
                    narrative_hint=(
                        "A shift this large is more often a collection defect than a "
                        "real event. Check source health and achieved coverage before "
                        "writing a security finding about it."
                    ),
                ))
            elif abs(change_pct) >= MATERIAL_CHANGE_PCT:
                r.notes.append(
                    f"{label} changed {change_pct:+.0f}% versus the prior run "
                    f"({before:.0f} -> {now:.0f})"
                )
        return r
