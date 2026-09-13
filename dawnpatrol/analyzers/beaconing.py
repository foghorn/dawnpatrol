"""Periodicity detection - the signature of live command-and-control.

Beaconing is the most reliable behavioural evidence of active malware available
without endpoint telemetry: a compromised host checks in on a timer. Unlike
domain reputation it survives hardcoded IPs, brand-new infrastructure, and abuse
of otherwise legitimate services.

The method is deliberately simple and explainable: take inter-arrival gaps for a
(client, destination) pair, and score how tightly they cluster. Low relative
dispersion with enough samples over enough elapsed time is a beacon.

Works on DNS timing today. It gets substantially stronger the moment a flow
source exists, because per-connection timing is not diluted by DNS caching.
"""

from __future__ import annotations

import statistics

from ..models import (
    AnalyzerResult,
    Entity,
    EntityType,
    EventKind,
    Metric,
    Severity,
    Signal,
)
from ..profile import Profile
from ..query import EventQuery
from .base import Analyzer
from .baseline import Baseline

MIN_SAMPLES = 12
MIN_SPAN_HOURS = 3.0
MAX_CV = 0.18          # coefficient of variation: stddev / mean
MIN_INTERVAL_S = 30.0
MAX_INTERVAL_S = 7200.0
MAX_PAIRS_TO_TEST = 400


def beacon_score(timestamps: list[float]) -> dict[str, float] | None:
    """Score a timestamp series for periodicity.

    Returns None when the series cannot be a beacon. Otherwise reports the
    interval, dispersion, and a 0-1 confidence derived from how tight the gaps
    are and how many periods were observed.
    """
    if len(timestamps) < MIN_SAMPLES:
        return None
    ordered = sorted(timestamps)
    span = ordered[-1] - ordered[0]
    if span < MIN_SPAN_HOURS * 3600:
        return None

    gaps = [b - a for a, b in zip(ordered, ordered[1:], strict=False) if b > a]
    if len(gaps) < MIN_SAMPLES - 1:
        return None

    mean_gap = statistics.fmean(gaps)
    if not (MIN_INTERVAL_S <= mean_gap <= MAX_INTERVAL_S):
        return None

    stdev = statistics.pstdev(gaps)
    cv = stdev / mean_gap if mean_gap else 1.0
    if cv > MAX_CV:
        return None

    # Confidence rises as jitter falls and as more periods are observed.
    tightness = max(0.0, 1.0 - (cv / MAX_CV))
    periods = min(1.0, len(gaps) / 60.0)
    return {
        "interval_seconds": round(mean_gap, 1),
        "jitter_seconds": round(stdev, 1),
        "cv": round(cv, 4),
        "samples": float(len(ordered)),
        "span_hours": round(span / 3600.0, 2),
        "confidence": round(0.45 + 0.5 * (0.6 * tightness + 0.4 * periods), 2),
    }


class BeaconingAnalyzer(Analyzer):
    name = "beaconing"
    requires_kinds = frozenset({EventKind.DNS, EventKind.FLOW, EventKind.FIREWALL})
    order = 40

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        kinds = q.kinds_present()
        found = 0

        if EventKind.DNS in kinds:
            found += self._dns_beacons(q, r, profile, baseline)
        if EventKind.FLOW in kinds:
            found += self._flow_beacons(q, r, profile, baseline)

        r.metrics.append(Metric(key="beacon.candidates", value=found, section="dns",
                                label="Beacon candidates",
                                prior=baseline.prior("beacon.candidates")))
        if EventKind.FLOW not in kinds:
            r.notes.append(
                "beaconing assessed from DNS timing only; no flow source is "
                "configured, so cached lookups and hardcoded-IP traffic are invisible "
                "to this analyzer"
            )
        return r

    # ----- DNS timing -------------------------------------------------------- #

    def _dns_beacons(self, q: EventQuery, r: AnalyzerResult,
                     profile: Profile, baseline: Baseline) -> int:
        pairs = [
            (client, domain, count)
            for client, domain, count in q.group_pairs(
                "client_ip", "domain", n=MAX_PAIRS_TO_TEST, kind=EventKind.DNS
            )
            if domain and count >= MIN_SAMPLES
        ]
        found = 0
        for client, domain, _count in pairs:
            if profile.is_benign_domain(domain):
                continue
            stamps = q.timestamps_for(limit=5000, kind=EventKind.DNS,
                                      client_ip=client, domain=domain)
            score = beacon_score([t.timestamp() for t in stamps])
            if score is None:
                continue
            found += 1
            recurrence = baseline.recurrence("c2.beacon_candidate", domain)
            caveat = profile.attribution_caveat(client)
            interval = score["interval_seconds"]
            r.signals.append(Signal(
                id=f"beacon.dns.{client}.{domain}",
                analyzer=self.name,
                title=(f"Periodic DNS from {profile.label_for(client)} to {domain} "
                       f"every ~{_human_interval(interval)}"),
                taxonomy="c2.beacon_candidate",
                severity_hint=Severity.MEDIUM,
                confidence=score["confidence"],
                entities=[
                    Entity(type=EntityType.IP, value=client, role="client"),
                    Entity(type=EntityType.DOMAIN, value=domain, role="destination"),
                ],
                evidence={
                    "client": client,
                    "domain": domain,
                    "interval_seconds": interval,
                    "jitter_seconds": score["jitter_seconds"],
                    "coefficient_of_variation": score["cv"],
                    "samples": int(score["samples"]),
                    "span_hours": score["span_hours"],
                    "attribution_caveat": caveat,
                    "prior_runs_with_this_domain": recurrence,
                },
                narrative_hint=(
                    "Regular-interval resolution with low jitter is the shape of an "
                    "automated check-in. Software updaters, telemetry, and NTP-like "
                    "services produce it legitimately - the question is whether this "
                    "client should be talking to this destination at all. Domain "
                    "reputation can corroborate but the timing is the evidence."
                ),
                days_recurring=recurrence,
            ))
        return found

    # ----- flow timing -------------------------------------------------------- #

    def _flow_beacons(self, q: EventQuery, r: AnalyzerResult,
                      profile: Profile, baseline: Baseline) -> int:
        pairs = [
            (src, dst, count)
            for src, dst, count in q.group_pairs(
                "src_ip", "dst_ip", n=MAX_PAIRS_TO_TEST, kind=EventKind.FLOW
            )
            if src and dst and count >= MIN_SAMPLES
            and profile.is_internal(src) and profile.is_external(dst)
        ]
        found = 0
        for src, dst, _count in pairs:
            stamps = q.timestamps_for(limit=5000, kind=EventKind.FLOW,
                                      src_ip=src, dst_ip=dst)
            score = beacon_score([t.timestamp() for t in stamps])
            if score is None:
                continue
            found += 1
            interval = score["interval_seconds"]
            r.signals.append(Signal(
                id=f"beacon.flow.{src}.{dst}",
                analyzer=self.name,
                title=(f"Periodic egress {profile.label_for(src)} -> {dst} "
                       f"every ~{_human_interval(interval)}"),
                taxonomy="c2.beacon_candidate",
                severity_hint=Severity.HIGH,
                confidence=min(0.95, score["confidence"] + 0.1),
                entities=[
                    Entity(type=EntityType.IP, value=src, role="source"),
                    Entity(type=EntityType.IP, value=dst, role="destination"),
                ],
                evidence={
                    "src": src,
                    "dst": dst,
                    "interval_seconds": interval,
                    "jitter_seconds": score["jitter_seconds"],
                    "coefficient_of_variation": score["cv"],
                    "samples": int(score["samples"]),
                    "span_hours": score["span_hours"],
                    "attribution_caveat": profile.attribution_caveat(src),
                },
                narrative_hint=(
                    "Connection-level periodicity is stronger evidence than DNS "
                    "timing: it is not diluted by caching and it survives hardcoded "
                    "destinations."
                ),
            ))
        return found


def _human_interval(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f}min"
    return f"{seconds / 3600:.1f}h"
