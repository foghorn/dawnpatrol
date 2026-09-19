"""Outbound data-volume signals - the closest thing to exfiltration detection
this pipeline can do without a flow source, and a case study in checking the
telemetry before trusting it.

Built against ``pkt_len`` (iptables' ``LEN=`` field) on ACCEPTed firewall
events, internal source to external destination. Two things were validated
against this deployment's live LibreNMS feed before this was written, not
assumed:

  * The segment gateways (IoT, DMZ) log DROP/REJECT only, never ACCEPT at all
    - already known from ``segment_review.py``'s own history. Confirmed
    again here: zero ACCEPT lines from either gateway in a 48h pull.
  * The edge router (the only device that logs any ACCEPT at all) logged
    **zero** internal-to-external ACCEPT lines in the same 48h window. Every
    ACCEPT line present was internal-to-internal (LAN<->DMZ), with a mean
    ``LEN`` of 51 bytes - a bare TCP control-packet size, not evidence of a
    bulk transfer.

So on this network, today, this analyzer will correctly report a near-zero
``fw.bytes.outbound_accepted`` metric and raise no signals - not because
nothing left the network, but because no accepted outbound session is
currently logged with a byte count at all. That is a genuine, confirmed
telemetry gap (see ``profile.yml``'s ``known_quirks``), not a bug in this
analyzer, and the metric's own data-quality note says so explicitly rather
than presenting silence as a clean bill of health. The code is written
generically against ``action=accept`` plus internal-src/external-dst, so it
activates with no changes here the moment either gap closes - an explicit
egress-ACCEPT log rule on the router, or a NetFlow/IPFIX source.

Even once real data flows through it, ``pkt_len`` is a per-packet length, not
a per-connection byte total - summing it only approximates real transferred
volume if the firewall logs every packet of a session, not just the one that
opened it. Every signal below is written to be read as directional evidence,
never a byte-accurate count (see each ``narrative_hint``).
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

#: Below this, even a full peer-relative outlier isn't worth a signal - a
#: quiet home network's routine traffic (updates, sync, calls) lives well
#: under it. Deliberately a plain module constant, not a profile.yml setting,
#: matching how every other analyzer's thresholds are tuned (DGA_MIN_LABEL,
#: NXDOMAIN_MIN_COUNT, ...) - a starting point, not a promise, since no real
#: bulk-transfer log volume has been observed on this router to calibrate
#: against yet.
SOURCE_BYTES_FLOOR = 50 * 1024 * 1024        # 50 MB
SOURCE_PEER_MULTIPLE = 5.0
MIN_SOURCES_FOR_PEER_COMPARISON = 3

LARGE_TRANSFER_BYTES_FLOOR = 200 * 1024 * 1024  # 200 MB, single (src, dst) pair
LARGE_TRANSFER_REPORT_LIMIT = 10


class DataVolumeAnalyzer(Analyzer):
    name = "data_volume"
    requires_kinds = frozenset({EventKind.FIREWALL})
    order = 55

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)

        pairs = q.bytes_by_pair(n=1000, kind=EventKind.FIREWALL, action="accept")
        egress = [
            (src, dst, total_bytes, hits) for src, dst, total_bytes, hits in pairs
            if src and dst and profile.is_internal(src) and not profile.is_internal(dst)
        ]

        total_egress_bytes = sum(total_bytes for _s, _d, total_bytes, _h in egress)
        r.metrics.append(Metric(
            key="fw.bytes.outbound_accepted", value=total_egress_bytes, section="perimeter",
            unit="bytes", label="Outbound accepted bytes (approx.)",
            prior=baseline.prior("fw.bytes.outbound_accepted"),
        ))

        if not egress:
            r.notes.append(
                "no internal-to-external ACCEPT firewall events carried a byte count this "
                "run - either nothing left through an accepted session, or (confirmed true "
                "for this deployment's edge router and both segment gateways as of 2026-09) "
                "outbound-accepted traffic simply isn't logged with a LEN= field. This metric "
                "cannot distinguish the two; see profile.yml's known_quirks for the confirmed "
                "gap and the fix."
            )
            return r

        self._source_outlier(egress, r, profile)
        self._large_transfer(egress, r, profile, baseline)
        return r

    # ----- per-source peer outlier -------------------------------------------- #

    def _source_outlier(self, egress: list[tuple[str, str, int, int]],
                        r: AnalyzerResult, profile: Profile) -> None:
        by_src: dict[str, int] = {}
        for src, _dst, total_bytes, _hits in egress:
            by_src[src] = by_src.get(src, 0) + total_bytes
        if len(by_src) < MIN_SOURCES_FOR_PEER_COMPARISON:
            return
        for src, total in by_src.items():
            if total < SOURCE_BYTES_FLOOR:
                continue
            # Peer mean excludes this source itself - otherwise the very
            # outlier being tested for would inflate its own baseline (the
            # same trap dns_anomalies.py's block/NXDOMAIN outliers avoid).
            peers = [b for other, b in by_src.items() if other != src]
            peer_mean = statistics.fmean(peers) if peers else 0.0
            if total < max(SOURCE_BYTES_FLOOR, peer_mean * SOURCE_PEER_MULTIPLE):
                continue
            caveat = profile.attribution_caveat(src)
            r.signals.append(Signal(
                id=f"data.volume_outlier.{src}",
                analyzer=self.name,
                title=f"{profile.label_for(src)} sent far more outbound data than its peers",
                taxonomy="data.volume_outlier",
                severity_hint=Severity.MEDIUM,
                confidence=0.5,
                entities=[Entity(type=EntityType.IP, value=src, role="source")],
                evidence={
                    "src": src,
                    "outbound_accepted_bytes": total,
                    "network_mean_bytes": round(peer_mean),
                    "multiple_of_mean": round(total / peer_mean, 1) if peer_mean else None,
                    "attribution_caveat": caveat,
                },
                narrative_hint=(
                    "Backups, cloud sync, OS updates, and video calls are all large "
                    "and completely routine - this is directional evidence at best. "
                    "pkt_len is a per-packet length, not a verified per-connection "
                    "byte total, and not every accepted session on this network is "
                    "logged packet-by-packet. Corroborate with the destination "
                    "(new? reputation?) and whether this source's role should "
                    "involve bulk outbound transfer at all before escalating."
                ),
            ))

    # ----- single large transfer ------------------------------------------------ #

    def _large_transfer(self, egress: list[tuple[str, str, int, int]],
                        r: AnalyzerResult, profile: Profile, baseline: Baseline) -> None:
        top = sorted(egress, key=lambda e: -e[2])[:LARGE_TRANSFER_REPORT_LIMIT]
        top = [pair for pair in top if pair[2] >= LARGE_TRANSFER_BYTES_FLOOR]
        if not top:
            return
        novel_dsts = set(baseline.novel(EntityType.IP, [dst for _s, dst, _b, _h in top]))
        for src, dst, total_bytes, hits in top:
            is_novel = dst in novel_dsts
            caveat = profile.attribution_caveat(src)
            r.signals.append(Signal(
                id=f"data.large_transfer.{src}.{dst}",
                analyzer=self.name,
                title=f"Large outbound transfer from {profile.label_for(src)} to {dst}",
                taxonomy="data.large_transfer",
                severity_hint=Severity.MEDIUM if is_novel else Severity.LOW,
                confidence=0.6 if is_novel else 0.45,
                entities=[
                    Entity(type=EntityType.IP, value=src, role="source"),
                    Entity(type=EntityType.IP, value=dst, role="destination"),
                ],
                evidence={
                    "src": src, "dst": dst,
                    "bytes": total_bytes, "hits": hits,
                    "destination_is_novel": is_novel,
                    "attribution_caveat": caveat,
                },
                narrative_hint=(
                    "A single large transfer to a destination this network has "
                    "talked to for a long time (a backup target, a cloud drive) is "
                    "routine. The same volume to a destination never seen before is "
                    "the more interesting case - check destination reputation and "
                    "whether the source is a device that should be doing this at "
                    "all."
                ),
            ))
