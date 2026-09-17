"""New-device detection: an internal IP making its first-ever appearance.

Reuses the same novelty mechanism `dns_anomalies.py` already applies to
domains - `Baseline.novel()` against the entities table - but for internal
client/source IPs instead of domains. Deliberately the cheapest possible way
to surface "something new joined the network": no MAC/DHCP parsing, no new
persistence of its own. Every event already feeds the entities table via
`store.entity_pairs_from_events()` (bumping `EntityType.IP` for every
`src_ip`/`client_ip`), so a device making its first-ever appearance is
already recorded - this analyzer is the first thing to actually read that
back and say so.

This is why a device behind a NAT-gated segment (no SNMP inventory, no local
DNS resolver) still gets caught here even though it never appears in the
curated device directory (`devices.py`): the entity table is fed straight
from firewall SRC=/DST= and DNS client_ip fields, not from any per-source
device list.
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
MAX_CANDIDATES = 500
MAX_REPORTED_PER_ZONE = 15


class NovelClientAnalyzer(Analyzer):
    name = "novel_clients"
    requires_kinds = frozenset({EventKind.DNS, EventKind.FIREWALL})
    order = 35

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        if not baseline.has_baseline():
            r.notes.append(
                "first run with data - every internal client is nominally new, "
                "so device novelty is not reported as a signal this time"
            )
            return r

        candidates: set[str] = set()
        for ip, _n in q.top("src_ip", n=MAX_CANDIDATES, kind=EventKind.FIREWALL):
            if ip and profile.is_internal(ip):
                candidates.add(ip)
        for ip, _n, _blk in q.dns_client_stats(n=MAX_CANDIDATES):
            if ip and profile.is_internal(ip):
                candidates.add(ip)
        if not candidates:
            return r

        novel = baseline.novel(EntityType.IP, sorted(candidates))
        if not novel:
            return r

        r.metrics.append(Metric(
            key="net.novel_clients", value=len(novel), section="general",
            label="New internal devices", prior=baseline.prior("net.novel_clients"),
        ))

        by_zone: dict[str, list[str]] = {}
        for ip in novel:
            by_zone.setdefault(profile.zone_of(ip) or "unknown", []).append(ip)

        for zone_name, ips in sorted(by_zone.items()):
            zone = profile.zone(zone_name)
            trust = zone.trust if zone else "unknown"
            severity = Severity.MEDIUM if trust in UNTRUSTED else Severity.LOW
            shown = sorted(ips)[:MAX_REPORTED_PER_ZONE]
            r.signals.append(Signal(
                id=f"net.novel_client.{zone_name}",
                analyzer=self.name,
                title=f"{len(ips)} new device(s) active on {zone_name} for the first time",
                taxonomy="net.novel_client",
                severity_hint=severity,
                confidence=0.55,
                entities=[Entity(type=EntityType.IP, value=ip, role="client") for ip in shown],
                evidence={
                    "zone": zone_name, "trust": trust, "count": len(ips),
                    "ips": [profile.label_for(ip) for ip in shown],
                },
                narrative_hint=(
                    "A first-ever-seen device is routine on most networks - a new "
                    "phone, a guest, a firmware-driven MAC rotation. It deserves "
                    "real attention on a segment meant to have a small, stable "
                    "population (IoT, DMZ); on the trusted LAN it is usually not "
                    "noteworthy by itself. Check what it's talking to before "
                    "treating its mere existence as a finding."
                ),
            ))
        return r
