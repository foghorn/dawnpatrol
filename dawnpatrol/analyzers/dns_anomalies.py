"""DNS statistics and anomaly detection.

DNS is usually the most compromise-relevant telemetry available, so this
analyzer does more real detection than the firewall ones: novel domains, DGA
shape, resolver bypass, and per-client block-rate outliers.
"""

from __future__ import annotations

import math
import re

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

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
DGA_MIN_LABEL = 12
DGA_MIN_ENTROPY = 3.6
NOVEL_REPORT_LIMIT = 25


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_dga(domain: str) -> tuple[bool, float, str]:
    """Heuristic DGA shape: a long, high-entropy, digit-mixed leftmost label."""
    parts = domain.split(".")
    if len(parts) < 2:
        return False, 0.0, ""
    label = parts[0]
    if len(label) < DGA_MIN_LABEL or not _LABEL_RE.match(label):
        return False, 0.0, label
    entropy = shannon_entropy(label)
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in "aeiou" for c in label) / len(label)
    # Random-looking labels are high entropy AND vowel-poor; long real words
    # (e.g. "documentation") are long but vowel-rich and lower entropy.
    suspicious = entropy >= DGA_MIN_ENTROPY and (vowels < 0.25 or digits > 0.3)
    return suspicious, entropy, label


class DNSAnomalyAnalyzer(Analyzer):
    name = "dns_anomalies"
    requires_kinds = frozenset({EventKind.DNS})
    order = 30

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        dns = {"kind": EventKind.DNS}

        total = q.count(**dns)
        if total == 0:
            r.notes.append("no DNS events in this run")
            return r

        blocked = q.count(blocked=True, **dns)
        unique_domains = q.distinct_count("domain", **dns)
        clients = q.distinct_count("client_ip", **dns)
        block_rate = round(100.0 * blocked / total, 2) if total else 0.0

        add = r.metrics.append
        add(Metric(key="dns.total", value=total, section="dns",
                   label="DNS queries", prior=baseline.prior("dns.total")))
        add(Metric(key="dns.blocked", value=blocked, section="dns",
                   label="Queries blocked", prior=baseline.prior("dns.blocked")))
        add(Metric(key="dns.block_rate", value=block_rate, section="dns", unit="%",
                   label="Block rate", prior=baseline.prior("dns.block_rate")))
        add(Metric(key="dns.unique_domains", value=unique_domains, section="dns",
                   label="Unique domains", prior=baseline.prior("dns.unique_domains")))
        add(Metric(key="dns.clients", value=clients, section="dns",
                   label="Active DNS clients", prior=baseline.prior("dns.clients")))

        for reason, count in q.top("block_reason", n=8, blocked=True, **dns):
            add(Metric(key=f"dns.block.{reason}", value=count, section="dns",
                       label=f"Blocked: {reason}"))

        for domain, count, blk in q.dns_domain_stats(n=25, blocked=True):
            add(Metric(key=f"dns.top_blocked.{domain}", value=count, section="dns_blocked",
                       label=domain))

        for client, count, blk in q.dns_client_stats(n=20):
            add(Metric(key=f"dns.client.{client}", value=count, section="dns_clients",
                       label=profile.label_for(client)))

        self._novel_domains(q, r, profile, baseline)
        self._dga(q, r, profile, baseline)
        self._resolver_bypass(q, r, profile)
        self._client_outliers(q, r, profile)
        return r

    # ----- novelty --------------------------------------------------------- #

    def _novel_domains(self, q: EventQuery, r: AnalyzerResult,
                       profile: Profile, baseline: Baseline) -> None:
        candidates = [
            d for d, _count, _blk in q.dns_domain_stats(n=4000)
            if d and not profile.is_benign_domain(d)
        ]
        if not candidates:
            return
        novel = baseline.novel(EntityType.DOMAIN, candidates)
        if not novel:
            return
        r.metrics.append(Metric(key="dns.novel_domains", value=len(novel), section="dns",
                                label="Newly-observed domains",
                                prior=baseline.prior("dns.novel_domains")))
        counts = {d: c for d, c, _ in q.dns_domain_stats(n=4000)}
        ranked = sorted(novel, key=lambda d: -counts.get(d, 0))[:NOVEL_REPORT_LIMIT]

        if not baseline.has_baseline():
            r.notes.append(
                "first run with DNS data - every domain is nominally novel, so "
                "novelty is not reported as a signal this time"
            )
            return

        r.signals.append(Signal(
            id="dns.novel_domains",
            analyzer=self.name,
            title=f"{len(novel)} newly-observed domains this period",
            taxonomy="dns.novel_domain",
            severity_hint=Severity.INFO,
            confidence=0.7,
            entities=[Entity(type=EntityType.DOMAIN, value=d) for d in ranked[:10]],
            evidence={
                "novel_count": len(novel),
                "top_novel": [{"domain": d, "queries": counts.get(d, 0)} for d in ranked],
            },
            narrative_hint=(
                "Novelty is context, not a verdict. A new domain matters when the "
                "client that asked for it is unexpected, or when the pattern is "
                "periodic. Check which client queried it before escalating."
            ),
        ))

    # ----- DGA shape --------------------------------------------------------- #

    def _dga(self, q: EventQuery, r: AnalyzerResult,
             profile: Profile, baseline: Baseline) -> None:
        hits = []
        for domain, count, _blk in q.dns_domain_stats(n=4000):
            if not domain or profile.is_benign_domain(domain):
                continue
            suspicious, entropy, label = looks_like_dga(domain)
            if suspicious:
                hits.append({"domain": domain, "queries": count,
                             "entropy": round(entropy, 2), "label_length": len(label)})
        if not hits:
            return
        hits.sort(key=lambda h: -h["entropy"])
        r.metrics.append(Metric(key="dns.dga_candidates", value=len(hits), section="dns",
                                label="DGA-shaped domains"))
        r.signals.append(Signal(
            id="dns.dga_candidates",
            analyzer=self.name,
            title=f"{len(hits)} domains with DGA-like structure",
            taxonomy="dns.dga_suspect",
            severity_hint=Severity.LOW,
            confidence=0.45,
            entities=[Entity(type=EntityType.DOMAIN, value=h["domain"]) for h in hits[:10]],
            evidence={"count": len(hits), "top": hits[:15]},
            narrative_hint=(
                "High-entropy labels are also produced by CDNs, telemetry, and "
                "cloud storage. Treat as a shortlist to check against client "
                "behaviour, not as evidence of a DGA on its own."
            ),
        ))

    # ----- resolver bypass ---------------------------------------------------- #

    def _resolver_bypass(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """Internal hosts reaching a DNS resolver other than the approved one.

        This is a genuine policy violation and one of the few DNS findings that
        stands on local evidence alone: it means the host's resolution is not
        being observed, which is exactly what malware wants.
        """
        approved = set(profile.policy.approved_resolvers)
        if not approved:
            return
        offenders: dict[str, int] = {}
        for src, dst, count in q.group_pairs("src_ip", "dst_ip", n=200,
                                             kind=EventKind.FIREWALL, dst_port=53):
            if not src or not dst or dst in approved:
                continue
            if profile.is_internal(src) and not profile.is_internal(dst):
                offenders[f"{src}->{dst}"] = offenders.get(f"{src}->{dst}", 0) + count
        if not offenders:
            return
        top = sorted(offenders.items(), key=lambda kv: -kv[1])[:10]
        entities = []
        for pair, _ in top:
            src, dst = pair.split("->")
            entities.append(Entity(type=EntityType.IP, value=src, role="client"))
            entities.append(Entity(type=EntityType.IP, value=dst, role="resolver"))
        r.signals.append(Signal(
            id="dns.resolver_bypass",
            analyzer=self.name,
            title="Internal hosts resolving DNS outside the approved resolver",
            taxonomy="dns.resolver_bypass",
            severity_hint=Severity.HIGH,
            confidence=0.85,
            entities=entities[:12],
            evidence={
                "approved_resolvers": sorted(approved),
                "observed": [{"pair": p, "queries": n} for p, n in top],
            },
            narrative_hint=(
                "A host resolving elsewhere is not being observed by the DNS "
                "sensor. This is a policy violation on local evidence alone and "
                "does not require reputation to justify."
            ),
        ))

    # ----- per-client outliers -------------------------------------------------- #

    def _client_outliers(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        stats = q.dns_client_stats(n=40)
        if len(stats) < 3:
            return
        rates = []
        for client, total, blocked in stats:
            if total < 200:
                continue
            rates.append((client, total, blocked, 100.0 * blocked / total))
        if not rates:
            return
        mean_rate = sum(x[3] for x in rates) / len(rates)
        for client, total, blocked, rate in rates:
            if rate < max(60.0, mean_rate * 2.5):
                continue
            caveat = profile.attribution_caveat(client)
            r.signals.append(Signal(
                id=f"dns.block_outlier.{client}",
                analyzer=self.name,
                title=f"{profile.label_for(client)} has an unusually high block rate",
                taxonomy="dns.client_block_outlier",
                severity_hint=Severity.LOW,
                confidence=0.6,
                entities=[Entity(type=EntityType.IP, value=client, role="client")],
                evidence={
                    "client": client,
                    "queries": total,
                    "blocked": blocked,
                    "block_rate_pct": round(rate, 1),
                    "network_mean_block_rate_pct": round(mean_rate, 1),
                    "attribution_caveat": caveat,
                },
                narrative_hint=(
                    "A high block rate usually means ad-heavy apps, not malware. "
                    "It is interesting when the client is a device that should be "
                    "quiet, such as an IoT endpoint."
                ),
            ))
