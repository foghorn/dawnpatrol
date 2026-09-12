"""Per-zone review driven entirely by the site profile.

Nothing here knows what an "IoT segment" is. Zones, their trust level, their
gateways, and their expected egress all come from profile.yml, so the same code
reviews any network.
"""

from __future__ import annotations

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

UNTRUSTED = {"untrusted", "semi-trusted", "dmz", "guest"}


class SegmentReviewAnalyzer(Analyzer):
    name = "segment_review"
    requires_kinds = frozenset({EventKind.DNS, EventKind.FIREWALL, EventKind.FLOW})
    order = 50

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        if not profile.zones:
            r.notes.append("no zones defined in the site profile; segment review skipped")
            return r

        for zone in profile.zones:
            dns_count = q.count(kind=EventKind.DNS, src_zone=zone.name)
            fw_out = q.count(kind=EventKind.FIREWALL, src_zone=zone.name)
            r.metrics.append(Metric(
                key=f"zone.{zone.name}.dns", value=dns_count, section="segments",
                label=f"{zone.name}: DNS queries",
                prior=baseline.prior(f"zone.{zone.name}.dns"),
            ))
            r.metrics.append(Metric(
                key=f"zone.{zone.name}.fw", value=fw_out, section="segments",
                label=f"{zone.name}: firewall events",
            ))

            if zone.expected_egress_domains and dns_count:
                self._unexpected_egress(q, r, profile, zone)
            if zone.trust in UNTRUSTED:
                self._inbound_to_zone(q, r, profile, zone)

        self._nat_notes(r, profile)
        return r

    # ----- egress outside the expected set ----------------------------------- #

    def _unexpected_egress(self, q: EventQuery, r: AnalyzerResult,
                           profile: Profile, zone) -> None:
        patterns = [p.lower().lstrip("*.") for p in zone.expected_egress_domains]
        unexpected: list[tuple[str, int]] = []
        for domain, count, _blk in q.dns_domain_stats(n=2000):
            if not domain:
                continue
            if any(domain == p or domain.endswith("." + p) for p in patterns):
                continue
            if profile.is_benign_domain(domain):
                continue
            hits = q.count(kind=EventKind.DNS, domain=domain, src_zone=zone.name)
            if hits:
                unexpected.append((domain, hits))
        if not unexpected:
            return
        unexpected.sort(key=lambda kv: -kv[1])
        severity = Severity.MEDIUM if zone.trust in UNTRUSTED else Severity.LOW
        r.signals.append(Signal(
            id=f"zone.{zone.name}.unexpected_egress",
            analyzer=self.name,
            title=f"{zone.name} resolved {len(unexpected)} domains outside its expected set",
            taxonomy="segment.unexpected_egress",
            severity_hint=severity,
            confidence=0.6,
            entities=[Entity(type=EntityType.DOMAIN, value=d) for d, _ in unexpected[:10]],
            evidence={
                "zone": zone.name,
                "trust": zone.trust,
                "expected": zone.expected_egress_domains,
                "unexpected": [{"domain": d, "queries": n} for d, n in unexpected[:20]],
                "attribution_caveat": profile.attribution_caveat(zone.gateway),
            },
            narrative_hint=(
                f"The profile declares what {zone.name} is supposed to talk to. "
                f"Anything else is worth explaining, especially for a device class "
                f"that cannot be patched."
            ),
        ))

    # ----- inbound reaching a sensitive zone ----------------------------------- #

    def _inbound_to_zone(self, q: EventQuery, r: AnalyzerResult,
                         profile: Profile, zone) -> None:
        accepted = q.group_pairs("src_ip", "dst_port", n=50,
                                 kind=EventKind.FIREWALL, action="accept",
                                 dst_zone=zone.name)
        external = [
            (src, port, count) for src, port, count in accepted
            if src and profile.is_external(src)
        ]
        if not external:
            return
        watched = set(profile.policy.attack_surface_ports)
        notable = [x for x in external if x[1] in watched] or external
        r.signals.append(Signal(
            id=f"zone.{zone.name}.inbound_accepted",
            analyzer=self.name,
            title=f"Inbound external sessions accepted into {zone.name}",
            taxonomy="segment.inbound_accepted",
            severity_hint=Severity.HIGH,
            confidence=0.8,
            entities=(
                [Entity(type=EntityType.IP, value=s, role="source") for s, _, _ in notable[:8]]
                + [Entity(type=EntityType.PORT, value=str(p), role="destination")
                   for _, p, _ in notable[:8] if p]
            ),
            evidence={
                "zone": zone.name,
                "trust": zone.trust,
                "accepted": [{"src": s, "dst_port": p, "hits": n} for s, p, n in notable[:20]],
            },
            narrative_hint=(
                "An accepted inbound session into a low-trust segment is materially "
                "different from a dropped probe. Confirm it corresponds to an "
                "intentional port-forward before treating it as an incident - and "
                "confirm the reverse before dismissing it."
            ),
        ))

    # ----- attribution limits ---------------------------------------------------- #

    def _nat_notes(self, r: AnalyzerResult, profile: Profile) -> None:
        for gateway in profile.policy.nat_attribution_limited_behind:
            caveat = profile.attribution_caveat(gateway)
            if caveat:
                r.notes.append(caveat)
