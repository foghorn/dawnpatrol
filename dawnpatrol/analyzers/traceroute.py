"""Traceroutes between internal zones.

A traceroute sends probes to one destination with the TTL set to 1, 2, 3 ...
so each router on the way reports itself. Whatever the protocol (Windows
``tracert`` uses ICMP, classic Unix ``traceroute`` uses UDP, ``tcptraceroute``
uses TCP), it leaves the same mark in a firewall log: packets from one source to
one destination carrying a ladder of consecutive low TTLs. Ordinary traffic
arrives with a TTL near its starting value (64, 128, 255) less a few hops, so a
ladder starting at 1 is hard to produce by accident.

Between internal zones, that is a host mapping the path into another segment:
routine when an administrator does it, and also an early step of lateral
movement. Mapping from a less trusted zone into a more trusted one is the shape
worth a human's attention.

Traceroutes from outside are left to ``firewall_patterns``' stepped-TTL check:
by the time an internet packet reaches the edge its TTL has already dropped by
many hops, so the internal ladder shape does not apply there.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

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
from .segment_review import UNTRUSTED

#: Highest TTL worth reading. A ladder lives at the bottom of the range;
#: ordinary traffic sits far above this, which keeps the query small.
LADDER_MAX_TTL = 30
#: A ladder must begin this low: traceroute starts at 1, a few tools skip ahead.
LADDER_MAX_START = 3
#: Consecutive TTL steps that make a ladder rather than coincidence.
LADDER_MIN_HOPS = 4
#: One source tracing this many internal destinations is mapping the network.
MAPPING_MIN_DESTINATIONS = 3

TAXONOMY = "recon.internal_traceroute"


def ladder_length(ttls: set[int]) -> int:
    """Consecutive steps upward from the lowest TTL, or 0 if it starts too high."""
    if not ttls:
        return 0
    start = min(ttls)
    if start > LADDER_MAX_START:
        return 0
    length = 0
    while start + length in ttls:
        length += 1
    return length


class TracerouteAnalyzer(Analyzer):
    name = "traceroute"
    requires_kinds = frozenset({EventKind.FIREWALL})
    order = 25

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for trace in _ladders(q.low_ttl_pairs(LADDER_MAX_TTL, kind=EventKind.FIREWALL)):
            src_zone = profile.zone_of(trace["src_ip"])
            dst_zone = profile.zone_of(trace["dst_ip"])
            # Same-zone traffic never crosses the firewall that logged it, and
            # traces from outside belong to the perimeter checks.
            if not profile.is_internal(trace["src_ip"]) \
                    or not profile.is_internal(trace["dst_ip"]) or src_zone == dst_zone:
                continue
            trace.update(src_zone=src_zone, dst_zone=dst_zone)
            by_source[trace["src_ip"]].append(trace)

        for src_ip, traces in sorted(by_source.items()):
            r.signals.append(self._signal(q, profile, baseline, src_ip, traces))

        r.metrics.append(Metric(
            key="recon.internal_traceroute_sources", value=len(by_source),
            section="segments", label="Hosts tracing routes into other zones",
        ))
        return r

    def _signal(self, q: EventQuery, profile: Profile, baseline: Baseline,
                src_ip: str, traces: list[dict[str, Any]]) -> Signal:
        traces.sort(key=lambda t: -t["probes"])
        src_zone = traces[0]["src_zone"]
        src_trust = _trust(profile, src_zone)
        # An unconfigured private range has unknown trust, so it never counts
        # as the more trusted side.
        into_trusted = src_trust in UNTRUSTED and any(
            _trust(profile, t["dst_zone"]) not in UNTRUSTED | {"unknown"} for t in traces)
        mapping = len(traces) >= MAPPING_MIN_DESTINATIONS
        severity = Severity.MEDIUM if into_trusted or mapping else Severity.LOW

        destinations = [t["dst_ip"] for t in traces]
        target = (f"{len(destinations)} hosts" if len(destinations) > 1
                  else profile.label_for(destinations[0]))
        support: list[str] = []
        for t in traces[:3]:
            support.extend(q.distinct_values("dedup_key", limit=10, kind=EventKind.FIREWALL,
                                             src_ip=src_ip, dst_ip=t["dst_ip"],
                                             proto=t["proto"]))
        return Signal(
            id=f"recon.traceroute.{src_ip}",
            analyzer=self.name,
            title=(f"{profile.label_for(src_ip)} traced routes from {src_zone} "
                   f"to {target}"),
            taxonomy=TAXONOMY,
            severity_hint=severity,
            confidence=0.8,
            entities=[Entity(type=EntityType.IP, value=src_ip, role="source")] + [
                Entity(type=EntityType.IP, value=d, role="destination")
                for d in destinations[:5]],
            evidence={
                "source_zone": src_zone,
                "source_trust": src_trust,
                "into_more_trusted_zone": into_trusted,
                "destinations": [
                    {"dst_ip": t["dst_ip"], "zone": t["dst_zone"], "proto": t["proto"],
                     "ttl_ladder": [t["ttl_start"], t["ttl_start"] + t["hops"] - 1],
                     "probes": t["probes"], "first_seen": t["first_seen"],
                     "last_seen": t["last_seen"]}
                    for t in traces[:10]
                ],
                "distinct_destinations": len(traces),
                "prior_runs_with_this_source": baseline.recurrence(TAXONOMY, src_ip),
            },
            narrative_hint=(
                "Consecutive low TTLs from one host to another are a traceroute, "
                "whatever the protocol. Between zones it is someone mapping the path "
                "into another segment: an administrator troubleshooting, or an early "
                "step of lateral movement. Check whether the source host has a reason "
                "to reach that segment, and whether anything else it did was accepted."
            ),
            support=support,
        )


def _ladders(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-TTL rows into one entry per (source, destination, protocol)
    whose TTLs form a ladder."""
    grouped: dict[tuple[str, str, str | None], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["src_ip"], row["dst_ip"], row["proto"])].append(row)
    out = []
    for (src_ip, dst_ip, proto), ttl_rows in grouped.items():
        hops = ladder_length({row["ttl"] for row in ttl_rows})
        if hops < LADDER_MIN_HOPS:
            continue
        first = min(row["first"] for row in ttl_rows)
        last = max(row["last"] for row in ttl_rows)
        out.append({
            "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
            "ttl_start": min(row["ttl"] for row in ttl_rows), "hops": hops,
            "probes": sum(row["n"] for row in ttl_rows),
            "first_seen": first.strftime("%Y-%m-%d %H:%M:%S") if first else None,
            "last_seen": last.strftime("%Y-%m-%d %H:%M:%S") if last else None,
        })
    return out


def _trust(profile: Profile, zone_name: str | None) -> str:
    zone = profile.zone(zone_name) if zone_name else None
    return zone.trust if zone else "unknown"
