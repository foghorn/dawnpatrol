"""Cross-source correlation.

The highest-value analysis available, and the one that only works because every
source normalizes into a single Event shape: a host that appears in both DNS and
firewall telemetry in an unusual way is far more interesting than one that
appears in either alone.
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


class CorrelationAnalyzer(Analyzer):
    name = "correlation"
    requires_kinds = frozenset({EventKind.DNS, EventKind.FIREWALL, EventKind.FLOW})
    order = 60

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        kinds = q.kinds_present()

        if {EventKind.DNS, EventKind.FIREWALL} <= kinds:
            self._dns_and_firewall(q, r, profile)
        self._watchlist_hits(q, r, profile, baseline)
        self._internal_scanning(q, r, profile)
        return r

    def _dns_and_firewall(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """Internal hosts that are both DNS-active and appear in firewall logs."""
        dns_clients = {c for c, _n, _b in q.dns_client_stats(n=60) if c}
        fw_sources = {ip for ip, _n in q.top("src_ip", n=200, kind=EventKind.FIREWALL)
                      if ip and profile.is_internal(ip)}
        both = sorted(dns_clients & fw_sources)
        if not both:
            return
        r.metrics.append(Metric(
            key="corr.dns_and_fw_hosts", value=len(both), section="general",
            label="Hosts active in both DNS and firewall logs",
        ))
        r.notes.append(
            f"{len(both)} internal hosts appear in both DNS and firewall telemetry; "
            f"cross-referenced for anomalies"
        )

    def _watchlist_hits(self, q: EventQuery, r: AnalyzerResult,
                        profile: Profile, baseline: Baseline) -> None:
        """Anything carried forward from a prior run that showed up again."""
        watch = baseline.watchlist()
        if not watch:
            return
        entity_types = {
            "domain": EntityType.DOMAIN,
            "ip": EntityType.IP,
            "host": EntityType.HOST,
        }
        for item in watch:
            value, etype = item["value"], item["type"]
            hits = 0
            if etype == "domain":
                hits = q.count(kind=EventKind.DNS, domain=value)
            elif etype == "ip":
                hits = q.count(src_ip=value) + q.count(dst_ip=value) + \
                       q.count(kind=EventKind.DNS, client_ip=value)
            elif etype == "host":
                # In practice the model uses "host" for an internal device
                # identified by its IP (matched the same way as "ip"), not a
                # named hostname - Event.device holds a syslog facility code
                # for this source, never a name, so it is checked too but
                # only ever adds coverage, never replaces the IP match.
                hits = q.count(src_ip=value) + q.count(dst_ip=value) + \
                       q.count(kind=EventKind.DNS, client_ip=value) + \
                       q.count(device=value)
            if hits <= 0:
                continue
            r.signals.append(Signal(
                id=f"corr.watchlist.{etype}.{value}",
                analyzer=self.name,
                title=f"Watchlisted {etype} {value} active again",
                taxonomy="watchlist.hit",
                severity_hint=Severity.MEDIUM,
                confidence=0.7,
                entities=[Entity(type=entity_types.get(etype, EntityType.IP), value=value)],
                evidence={
                    "entity": value,
                    "entity_type": etype,
                    "events_this_period": hits,
                    "watch_reason": item.get("reason", ""),
                    "watch_expires": item.get("expires", ""),
                },
                narrative_hint=(
                    "This was flagged for follow-up in an earlier run. Resolve it or "
                    "extend the watch; an item that recurs indefinitely without a "
                    "decision is noise."
                ),
            ))

    def _internal_scanning(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """An internal host probing many ports looks like lateral movement.

        Only visible when internal traffic actually traverses a logging device,
        which is why the note below matters as much as the detection.
        """
        for p in q.source_profile(n=40, kind=EventKind.FIREWALL):
            ip = p["src_ip"]
            if not ip or not profile.is_internal(ip):
                continue
            if p["distinct_dst_ports"] < 20 or p["hits"] < 50:
                continue
            r.signals.append(Signal(
                id=f"corr.internal_scan.{ip}",
                analyzer=self.name,
                title=f"Internal host {profile.label_for(ip)} probed many destination ports",
                taxonomy="lateral.internal_scan",
                severity_hint=Severity.HIGH,
                confidence=0.65,
                entities=[Entity(type=EntityType.IP, value=ip, role="source")],
                evidence={
                    "src": ip,
                    "hits": p["hits"],
                    "distinct_destination_ports": p["distinct_dst_ports"],
                    "duration_hours": p["duration_hours"],
                },
                narrative_hint=(
                    "Broad port probing from inside the network is either an "
                    "authorized scanner or a compromised host enumerating targets. "
                    "Determine which; there is no benign third option."
                ),
            ))
