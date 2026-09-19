"""DNS statistics and anomaly detection.

DNS is usually the most compromise-relevant telemetry available, so this
analyzer does more real detection than the firewall ones: novel domains, DGA
shape, resolver bypass, per-client block/NXDOMAIN-rate outliers, and two
DNS tunneling shapes (subdomain fan-out, TXT/NULL concentration).
"""

from __future__ import annotations

import math
import re
import statistics
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

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
DGA_MIN_LABEL = 12
DGA_MIN_ENTROPY = 3.6
NOVEL_REPORT_LIMIT = 25
NXDOMAIN_MIN_COUNT = 30
NXDOMAIN_RATE_FLOOR = 15.0
NXDOMAIN_RATE_MULTIPLE = 4.0

#: A small, deliberately incomplete list of two-label public suffixes -
#: enough to keep unrelated organizations that happen to share a ccTLD
#: second-level domain (two sites under "co.uk" are not the same apex) from
#: being merged into one false "apex" by a naive last-two-labels split. Not a
#: full public-suffix implementation, the same heuristic-not-perfect
#: tradeoff `looks_like_dga` already makes for its own shape.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "co.jp", "co.nz", "co.za", "co.in", "co.kr", "co.il",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "com.mx", "com.cn", "com.tw", "com.sg", "com.hk",
})

#: DNS tunneling: a single client resolving many distinct, mostly-unique-use
#: subdomains of one apex. Each encoded query typically carries a slice of
#: data in the subdomain itself, so almost every one differs from the last -
#: the uniqueness ratio is what separates this from a legitimate high-volume
#: domain (repeatedly resolving the *same* few names).
TUNNEL_MIN_DISTINCT_SUBDOMAINS = 40
TUNNEL_MIN_UNIQUENESS_RATIO = 0.8

#: DNS tunneling, second shape: TXT and NULL are the classic payload-carrying
#: record types (larger response per query) for tools like iodine, dnscat2,
#: and Cobalt Strike's DNS beacon. Legitimate TXT use (SPF/DKIM/domain
#: verification) is rare and low-volume per domain; NULL is virtually never
#: used at all outside tunneling.
TUNNEL_QTYPES = ("TXT", "NULL")
TUNNEL_QTYPE_MIN_COUNT = 20
TUNNEL_QTYPE_MIN_RATIO = 0.5
TUNNEL_QTYPE_REPORT_LIMIT = 100


def apex_domain(domain: str) -> str:
    """Best-effort registrable domain: the last two labels, or three when the
    last two are a known ccTLD second-level suffix (co.uk, com.au, ...).
    See `_TWO_LABEL_SUFFIXES` for the tradeoff this makes."""
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return domain
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


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

        for domain, count, _blk in q.dns_domain_stats(n=25, blocked=True):
            add(Metric(key=f"dns.top_blocked.{domain}", value=count, section="dns_blocked",
                       label=domain))

        for client, count, _blk in q.dns_client_stats(n=20):
            add(Metric(key=f"dns.client.{client}", value=count, section="dns_clients",
                       label=profile.label_for(client)))

        self._novel_domains(q, r, profile, baseline)
        self._dga(q, r, profile, baseline)
        self._resolver_bypass(q, r, profile)
        self._client_outliers(q, r, profile)
        self._nxdomain_outliers(q, r, profile)
        self._tunnel_fanout(q, r, profile)
        self._tunnel_qtype_outliers(q, r, profile)
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

    # ----- per-client NXDOMAIN outliers ------------------------------------------ #

    def _nxdomain_outliers(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """A client resolving far more nonexistent domains than its peers.

        Distinct from the block-rate outlier above: an ad-heavy app blocked by
        Pi-hole is routine and can legitimately run 20-40%+. A client burning
        through many NXDOMAIN responses is a different shape - it is what a
        DGA trying dozens of unregistered candidate domains looks like, or a
        misconfigured app retrying a dead hostname. Legitimate mDNS/NetBIOS
        chatter also produces some NXDOMAIN baseline, which is why this
        compares against the network's own mean rather than an absolute cutoff
        alone.
        """
        stats = q.dns_client_stats(n=40)
        if len(stats) < 3:
            return
        nx_by_client = {
            client: count for client, _reason, count in
            q.group_pairs("client_ip", "block_reason", n=200,
                         kind=EventKind.DNS, block_reason="NXDOMAIN")
        }
        rates = []
        for client, total, _blocked in stats:
            if total < 200:
                continue
            nx = nx_by_client.get(client, 0)
            if nx < NXDOMAIN_MIN_COUNT:
                continue
            rates.append((client, total, nx, 100.0 * nx / total))
        if not rates:
            return
        for i, (client, total, nx, rate) in enumerate(rates):
            # Compare against peers' mean, excluding this client itself -
            # otherwise the very outlier being tested for pulls its own
            # baseline up (the same trap the deauth-outlier check avoids).
            peers = [x[3] for j, x in enumerate(rates) if j != i]
            peer_mean = statistics.fmean(peers) if peers else 0.0
            if rate < max(NXDOMAIN_RATE_FLOOR, peer_mean * NXDOMAIN_RATE_MULTIPLE):
                continue
            caveat = profile.attribution_caveat(client)
            r.signals.append(Signal(
                id=f"dns.nxdomain_outlier.{client}",
                analyzer=self.name,
                title=f"{profile.label_for(client)} has an unusually high NXDOMAIN rate",
                taxonomy="dns.nxdomain_outlier",
                severity_hint=Severity.LOW,
                confidence=0.5,
                entities=[Entity(type=EntityType.IP, value=client, role="client")],
                evidence={
                    "client": client,
                    "queries": total,
                    "nxdomain": nx,
                    "nxdomain_rate_pct": round(rate, 1),
                    "peer_mean_nxdomain_rate_pct": round(peer_mean, 1),
                    "attribution_caveat": caveat,
                },
                narrative_hint=(
                    "A high NXDOMAIN rate is what a DGA trying many unregistered "
                    "candidate domains looks like, or a misconfigured app retrying "
                    "a dead hostname - it is not itself proof of either. mDNS and "
                    "NetBIOS chatter produce some baseline NXDOMAIN traffic on any "
                    "network, which is why this compares against the network mean "
                    "rather than firing on a bare threshold."
                ),
            ))

    # ----- DNS tunneling: subdomain fan-out --------------------------------------- #

    def _tunnel_fanout(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """One client resolving many distinct, mostly-unique subdomains of a
        single apex domain - the core DNS tunneling shape, since each
        encoded query typically carries a slice of data in the subdomain
        itself. The uniqueness ratio (distinct subdomains / total queries to
        that apex) is what separates this from ordinary high-volume access
        to a domain, which mostly re-resolves the same handful of names.
        """
        pairs = q.dns_client_domain_stats(limit=50000)
        if not pairs:
            return
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for client, domain, queries in pairs:
            if not client or not domain:
                continue
            apex = apex_domain(domain)
            if profile.is_benign_domain(apex):
                continue
            slot = grouped.setdefault((client, apex), {"subdomains": set(), "total": 0})
            slot["subdomains"].add(domain)
            slot["total"] += queries

        for (client, apex), slot in grouped.items():
            distinct = len(slot["subdomains"])
            total = slot["total"]
            if distinct < TUNNEL_MIN_DISTINCT_SUBDOMAINS:
                continue
            ratio = distinct / total if total else 0.0
            if ratio < TUNNEL_MIN_UNIQUENESS_RATIO:
                continue
            confidence = 0.5
            if ratio >= 0.95:
                confidence += 0.2
            if distinct >= 200:
                confidence += 0.2
            caveat = profile.attribution_caveat(client)
            r.signals.append(Signal(
                id=f"dns.tunnel_suspect.{client}.{apex}",
                analyzer=self.name,
                title=f"{profile.label_for(client)} resolved {distinct} distinct "
                     f"subdomains of {apex}",
                taxonomy="dns.tunnel_suspect",
                severity_hint=Severity.MEDIUM,
                confidence=round(min(confidence, 0.9), 2),
                entities=[
                    Entity(type=EntityType.IP, value=client, role="client"),
                    Entity(type=EntityType.DOMAIN, value=apex, role="apex"),
                ],
                evidence={
                    "client": client,
                    "apex": apex,
                    "distinct_subdomains": distinct,
                    "total_queries": total,
                    "uniqueness_ratio": round(ratio, 2),
                    "sample_subdomains": sorted(slot["subdomains"])[:10],
                    "attribution_caveat": caveat,
                },
                narrative_hint=(
                    "A high volume of distinct, almost-never-repeated subdomains "
                    "under one apex is the core DNS tunneling shape - encoded data "
                    "usually lives in the subdomain itself, so nearly every query "
                    "differs from the last. Content-delivery, telemetry, and "
                    "analytics platforms can look similar; check whether the apex "
                    "is a known CDN/analytics provider not yet in the "
                    "benign-domain list before escalating."
                ),
            ))

    # ----- DNS tunneling: TXT/NULL concentration ------------------------------------ #

    def _tunnel_qtype_outliers(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        """TXT and NULL are the classic payload-carrying record types for DNS
        tunneling tools - a larger response fits per query than a bare A
        record allows. Flagged on an absolute floor *and* a concentration
        ratio against that domain's own total query volume, since a handful
        of legitimate SPF/DKIM TXT lookups is routine and must not fire this
        on its own.
        """
        candidates = q.top("domain", n=TUNNEL_QTYPE_REPORT_LIMIT,
                           kind=EventKind.DNS, qtype=list(TUNNEL_QTYPES))
        if not candidates:
            return
        hits = []
        for domain, tn_count in candidates:
            if not domain or tn_count < TUNNEL_QTYPE_MIN_COUNT or profile.is_benign_domain(domain):
                continue
            total = q.count(domain=domain, kind=EventKind.DNS)
            ratio = tn_count / total if total else 0.0
            if ratio < TUNNEL_QTYPE_MIN_RATIO:
                continue
            hits.append({
                "domain": domain, "txt_null_queries": tn_count,
                "total_queries": total, "ratio_pct": round(ratio * 100, 1),
            })
        if not hits:
            return
        hits.sort(key=lambda h: -h["txt_null_queries"])
        r.metrics.append(Metric(
            key="dns.tunnel_qtype_candidates", value=len(hits), section="dns",
            label="Domains with unusual TXT/NULL query concentration",
        ))
        r.signals.append(Signal(
            id="dns.tunnel_qtype_candidates",
            analyzer=self.name,
            title=f"{len(hits)} domain(s) with an unusual TXT/NULL query concentration",
            taxonomy="dns.tunnel_qtype_suspect",
            severity_hint=Severity.MEDIUM,
            confidence=0.5,
            entities=[Entity(type=EntityType.DOMAIN, value=h["domain"]) for h in hits[:10]],
            evidence={"count": len(hits), "top": hits[:15]},
            narrative_hint=(
                "TXT and NULL records let a tunneling tool carry more payload "
                "per response than a bare A/AAAA query would. Legitimate TXT use "
                "(SPF, DKIM, domain verification) is rare and low-volume per "
                "domain, which is why this requires both an absolute floor and a "
                "concentration ratio, not a bare count."
            ),
        ))
