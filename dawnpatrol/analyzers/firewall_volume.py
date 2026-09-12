"""Firewall volume statistics: the numbers that go straight into the report.

This analyzer produces almost no signals on purpose. Volume is context, not a
finding - mass scanning of any public address is constant and normal. Its job is
to compute the statistics tables so the model never has to, and to flag only
genuinely anomalous shape (a spike that dwarfs the median).
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

SPIKE_MULTIPLE = 3.0
MIN_HOURS_FOR_SPIKE = 6


class FirewallVolumeAnalyzer(Analyzer):
    name = "firewall_volume"
    requires_kinds = frozenset({EventKind.FIREWALL})
    order = 10

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        fw = {"kind": EventKind.FIREWALL}

        total = q.count(**fw)
        drops = q.count(action="drop", **fw)
        accepts = q.count(action="accept", **fw)
        rejects = q.count(action="reject", **fw)
        system = q.count(kind=EventKind.SYSTEM)
        unique_src = q.distinct_count("src_ip", **fw)

        add = r.metrics.append
        add(Metric(key="fw.total", value=total, section="perimeter",
                   label="Firewall log lines", prior=baseline.prior("fw.total")))
        add(Metric(key="fw.drops", value=drops, section="perimeter",
                   label="Firewall DROPs", prior=baseline.prior("fw.drops")))
        add(Metric(key="fw.accepts", value=accepts, section="perimeter",
                   label="Firewall ACCEPTs", prior=baseline.prior("fw.accepts")))
        add(Metric(key="fw.rejects", value=rejects, section="perimeter",
                   label="Firewall REJECTs"))
        add(Metric(key="sys.events", value=system, section="router",
                   label="System/service events", prior=baseline.prior("sys.events")))
        add(Metric(key="fw.unique_sources", value=unique_src, section="perimeter",
                   label="Unique external source IPs",
                   prior=baseline.prior("fw.unique_sources")))

        # Protocol and ingress-interface shape.
        for proto, count in q.top("proto", n=8, **fw):
            add(Metric(key=f"fw.proto.{proto}", value=count, section="perimeter",
                       label=f"Protocol {proto}"))
        for iface, count in q.top("iface_in", n=6, **fw):
            add(Metric(key=f"fw.iface.{iface}", value=count, section="perimeter",
                       label=f"Ingress {iface}"))

        # Ports: by hit count, and separately by distinct sources. A port hit by
        # many distinct IPs is a broader scanning signal than the same count
        # from one host, and the two rankings rarely agree.
        top_ports = q.top("dst_port", n=20, action="drop", **fw)
        for port, count in top_ports:
            add(Metric(key=f"fw.port.hits.{port}", value=count, section="ports",
                       label=f"Port {port} hits"))
        for port, uniq in q.top("dst_port", n=20, by="unique:src_ip", action="drop", **fw):
            add(Metric(key=f"fw.port.sources.{port}", value=uniq, section="ports",
                       label=f"Port {port} distinct sources"))

        # Attack-surface ports called out explicitly, present or not.
        watched = set(profile.policy.attack_surface_ports)
        port_hits = dict(q.top("dst_port", n=200, action="drop", **fw))
        for port in sorted(watched):
            hits = int(port_hits.get(port, 0))
            if hits:
                add(Metric(key=f"fw.attack_port.{port}", value=hits, section="ports",
                           label=f"Attack-surface port {port}"))

        # Hourly distribution and spike attribution.
        hourly = q.hourly(action="drop", **fw)
        if hourly:
            counts = list(hourly.values())
            median = statistics.median(counts)
            mean = statistics.fmean(counts)
            peak_hour, peak_count = max(hourly.items(), key=lambda kv: kv[1])
            add(Metric(key="fw.hourly.median", value=round(median, 1), section="perimeter",
                       label="Median DROPs/hour"))
            add(Metric(key="fw.hourly.mean", value=round(mean, 1), section="perimeter",
                       label="Mean DROPs/hour"))
            add(Metric(key="fw.peak_hour", value=peak_hour, section="perimeter",
                       label="Peak DROP hour"))
            add(Metric(key="fw.peak_hour_count", value=peak_count, section="perimeter",
                       label="Peak hour DROPs"))

            # Only meaningful with enough coverage; a spike computed over two
            # retrieved hours is an artefact of truncation, not an event.
            if len(counts) >= MIN_HOURS_FOR_SPIKE and median > 0 and peak_count > median * SPIKE_MULTIPLE:
                attribution = q.top("src_ip", n=3, action="drop", **fw)
                r.signals.append(Signal(
                    id=f"fw.spike.{peak_hour.replace(' ', 'T')}",
                    analyzer=self.name,
                    title=f"DROP volume spike at {peak_hour}",
                    taxonomy="volume.spike",
                    severity_hint=Severity.LOW,
                    confidence=0.55,
                    entities=[Entity(type=EntityType.HOST, value="perimeter", role="target")],
                    evidence={
                        "hour": peak_hour,
                        "count": peak_count,
                        "median_hourly": round(median, 1),
                        "multiple_of_median": round(peak_count / median, 1),
                        "hours_observed": len(counts),
                        "top_sources_in_window": [
                            {"ip": ip, "hits": n} for ip, n in attribution
                        ],
                    },
                    narrative_hint=(
                        "Attribute the spike to a source before treating it as an "
                        "event. A single scanner burst is ordinary."
                    ),
                ))

        r.notes.append(
            f"volume: {total} firewall lines, {drops} drops, {unique_src} unique sources"
        )
        return r
