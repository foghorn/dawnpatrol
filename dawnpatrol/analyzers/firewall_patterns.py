"""Behavioural classification of firewall sources.

Classification happens here, from local evidence only. Reputation is applied
later, by the agent, and can only corroborate - never lead. Chasing scores
instead of behaviour is how a report ends up full of whitelisted cloud IPs
described as threats.

Four shapes, each with a distinct signature:

  persistent prober   one source, one fixed port, sustained over hours
  mass scanner sweep  many IPs in a /24, ~1 hit each, broad ports, even spread
  stepped-TTL probe   UDP, fixed length, TTL incrementing across a burst
  conntrack return    TCP from sport 80/443 to random high ports (benign)
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

PROBER_MIN_HITS = 50
PROBER_MIN_HOURS = 2.0
PROBER_MAX_PORTS = 3
SWEEP_MIN_SOURCES = 15
SWEEP_MAX_HITS_PER_SOURCE = 4.0


class FirewallPatternAnalyzer(Analyzer):
    name = "firewall_patterns"
    requires_kinds = frozenset({EventKind.FIREWALL})
    order = 20

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        fw = {"kind": EventKind.FIREWALL, "action": "drop"}
        watched_ports = set(profile.policy.attack_surface_ports)

        profiles = q.source_profile(n=60, **fw)
        sweep_members = self._sweep_members(q, r, profile, **fw)

        return_hits = q.return_traffic_count(**fw)
        if return_hits:
            r.metrics.append(Metric(
                key="fw.conntrack_return", value=return_hits, section="perimeter",
                label="Conntrack-timeout return traffic",
            ))
            r.notes.append(
                f"{return_hits} drops are TCP sourced from port 80/443 - outbound "
                f"session return traffic dropped on conntrack timeout, not inbound attack"
            )

        for p in profiles:
            ip = p["src_ip"]
            if not ip or not profile.is_external(ip) or ip in sweep_members:
                continue
            ports = q.ports_for_source(ip, n=6)
            if not ports:
                continue
            top_port, top_port_hits = ports[0]
            concentration = top_port_hits / max(1, p["hits"])

            # Conntrack return traffic: skip, it is benign by construction.
            if q.return_traffic_count(src_ip=ip, **fw) > p["hits"] * 0.8:
                continue

            is_prober = (
                p["hits"] >= PROBER_MIN_HITS
                and p["duration_hours"] >= PROBER_MIN_HOURS
                and p["distinct_dst_ports"] <= PROBER_MAX_PORTS
                and concentration >= 0.7
            )
            if not is_prober:
                continue

            targets_service = top_port in watched_ports
            severity = Severity.MEDIUM if targets_service else Severity.LOW
            recurrence = baseline.recurrence("scan.persistent_prober", ip)

            r.signals.append(Signal(
                id=f"fw.prober.{ip}.{top_port}",
                analyzer=self.name,
                title=f"Sustained probe from {ip} against port {top_port}",
                taxonomy="scan.persistent_prober",
                severity_hint=severity,
                confidence=0.75 if targets_service else 0.6,
                entities=[
                    Entity(type=EntityType.IP, value=ip, role="source"),
                    Entity(type=EntityType.PORT, value=str(top_port), role="destination"),
                ],
                evidence={
                    "hits": p["hits"],
                    "duration_hours": p["duration_hours"],
                    "first_seen": p["first_seen"],
                    "last_seen": p["last_seen"],
                    "distinct_destination_ports": p["distinct_dst_ports"],
                    "top_port": top_port,
                    "top_port_hits": top_port_hits,
                    "port_concentration": round(concentration, 2),
                    "ttl_range": [p["ttl_min"], p["ttl_max"]],
                    "targets_attack_surface_port": targets_service,
                    "prior_runs_with_this_source": recurrence,
                },
                narrative_hint=(
                    "Single source, fixed destination port, sustained over hours - "
                    "matches a targeted prober rather than the one-hit-per-IP shape "
                    "of a scanner sweep. Reputation may corroborate but cannot "
                    "create or override this classification."
                ),
                days_recurring=recurrence,
            ))

        self._stepped_ttl(q, r, profile, **fw)
        r.metrics.append(Metric(
            key="fw.probers", value=len([s for s in r.signals
                                         if s.taxonomy == "scan.persistent_prober"]),
            section="perimeter", label="Persistent probers",
        ))
        return r

    # ----- sweeps ------------------------------------------------------------- #

    def _sweep_members(self, q: EventQuery, r: AnalyzerResult,
                       profile: Profile, **filters) -> set[str]:
        """Identify /24 sweeps and return their member IPs, so they are not
        double-reported as individual probers."""
        members: set[str] = set()
        spreads = q.subnet_spread(n=12, **filters)
        for prefix, sources, hits in spreads:
            if sources < SWEEP_MIN_SOURCES:
                continue
            per_source = hits / sources
            if per_source > SWEEP_MAX_HITS_PER_SOURCE:
                continue
            octets = prefix.split("/")[0].rsplit(".", 1)[0]
            for ip, _ in q.top("src_ip", n=5000, **filters):
                if ip and ip.startswith(octets + "."):
                    members.add(ip)
            r.signals.append(Signal(
                id=f"fw.sweep.{prefix.replace('/', '_')}",
                analyzer=self.name,
                title=f"Mass scanner sweep from {prefix}",
                taxonomy="scan.mass_sweep",
                severity_hint=Severity.INFO,
                confidence=0.8,
                entities=[Entity(type=EntityType.IP, value=prefix, role="source")],
                evidence={
                    "prefix": prefix,
                    "distinct_sources": sources,
                    "total_hits": hits,
                    "hits_per_source": round(per_source, 2),
                },
                narrative_hint=(
                    "Many addresses in one /24, roughly one hit each - commercial "
                    "scan infrastructure. Baseline internet noise. One line in the "
                    "report, not a paragraph; enrich two representatives at most."
                ),
            ))
        if spreads:
            r.metrics.append(Metric(
                key="fw.sweeps", value=len([s for s in r.signals
                                            if s.taxonomy == "scan.mass_sweep"]),
                section="perimeter", label="Scanner sweeps",
            ))
        return members

    # ----- stepped TTL --------------------------------------------------------- #

    def _stepped_ttl(self, q: EventQuery, r: AnalyzerResult,
                     profile: Profile, **filters) -> None:
        for p in q.source_profile(n=30, proto="udp", **filters):
            ip = p["src_ip"]
            ttl_min, ttl_max = p["ttl_min"], p["ttl_max"]
            if not ip or ttl_min is None or ttl_max is None:
                continue
            # A traceroute-style or spoofed probe walks TTL across a burst;
            # ordinary traffic from one host holds it nearly constant.
            if ttl_min <= 8 and (ttl_max - ttl_min) >= 4 and p["hits"] >= 10:
                r.signals.append(Signal(
                    id=f"fw.stepped_ttl.{ip}",
                    analyzer=self.name,
                    title=f"Stepped-TTL UDP probe from {ip}",
                    taxonomy="scan.stepped_ttl",
                    severity_hint=Severity.LOW,
                    confidence=0.5,
                    entities=[Entity(type=EntityType.IP, value=ip, role="source")],
                    evidence={
                        "hits": p["hits"],
                        "ttl_range": [ttl_min, ttl_max],
                        "distinct_destination_ports": p["distinct_dst_ports"],
                        "duration_hours": p["duration_hours"],
                    },
                    narrative_hint=(
                        "TTL incrementing across a burst is consistent with "
                        "traceroute-style mapping or a spoofed reflection probe. "
                        "Worth noting; not worth alarm without corroboration."
                    ),
                ))
