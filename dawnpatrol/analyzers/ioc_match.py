"""Match the run's traffic and DNS lookups against operator-supplied IoC lists.

Lists live in DAWNPATROL_IOC_PATHS (default ``/etc/dawnpatrol/iocs``); see
``iocs.py`` for the formats. Every distinct address and domain in the run is
checked - not a top-N - because the contact that matters is usually a single
probe or a single lookup.

One signal per matched indicator. Its severity is the list's own (tier T1-T4 or
a severity column), with one adjustment: when every contact was inbound and
the firewall dropped or rejected all of it, the signal is capped at LOW. A
listed address knocking on a closed door is worth recording, not worth an
AMBER report; an internal host reaching out to it, or anything accepted, keeps
the list's full severity.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..iocs import Indicator, IocSet, ioc_paths, load_iocs
from ..models import AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from ..secrets import read_env
from .base import Analyzer
from .baseline import Baseline

_BLOCKED = {"drop", "reject", "deny", "block"}
_TIER_CONFIDENCE = {"T1": 0.9, "T2": 0.7, "T3": 0.5, "T4": 0.2}
_MAX_LISTED = 10


class IocMatchAnalyzer(Analyzer):
    name = "ioc_match"
    requires_kinds = frozenset({EventKind.FIREWALL, EventKind.FLOW, EventKind.DNS,
                                EventKind.HTTP, EventKind.AUTH, EventKind.OTHER})
    order = 60

    def __init__(self, iocs: IocSet | None = None) -> None:
        self._iocs = iocs

    def _load(self) -> IocSet:
        if self._iocs is None:
            self._iocs = load_iocs(ioc_paths(read_env("DAWNPATROL_IOC_PATHS", "")))
        return self._iocs

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name)
        iocs = self._load()
        if not iocs.indicators:
            return result
        result.notes.append(f"IoC lists: {iocs.summary()}")

        ip_hits = iocs.match_ips(q.all_traffic_ips())
        dom_hits = iocs.match_domains(q.all_dns_domains())

        # indicator -> the concrete addresses/domains it matched this run
        by_indicator: dict[Indicator, set[str]] = {}
        for value, inds in (ip_hits | dom_hits).items():
            for ind in inds:
                by_indicator.setdefault(ind, set()).add(value)

        traffic = q.traffic_involving(sorted(ip_hits)) if ip_hits else []
        lookups = q.lookups_of(sorted(dom_hits)) if dom_hits else []

        for ind, values in sorted(by_indicator.items(),
                                  key=lambda kv: (-kv[0].severity, kv[0].value)):
            if ind.kind in ("ip", "cidr"):
                signal = self._ip_signal(ind, values, traffic, profile)
            else:
                signal = self._domain_signal(ind, values, lookups)
            if signal is not None:
                result.signals.append(signal)

        # Text indicators: user agents (HTTP requests, cloud API calls) and
        # markers inside requested URLs.
        ua_hits = iocs.match_user_agents(q.all_user_agents())
        by_ua: dict[Indicator, set[str]] = {}
        for value, inds in ua_hits.items():
            for ind in inds:
                by_ua.setdefault(ind, set()).add(value)
        for ind, values in sorted(by_ua.items(), key=lambda kv: -kv[0].severity):
            rows = q.detail_rows(user_agent=sorted(values), limit=5000)
            if rows:
                result.signals.append(self._text_signal(
                    ind, rows, "ioc.user_agent_match",
                    f"IoC-listed user agent {ind.value!r} seen", sorted(values)))
        for ind in iocs.url_markers():
            rows = q.detail_rows(kind=EventKind.HTTP, raw_contains=ind.value, limit=5000)
            rows = [r for r in rows if ind.value in (r["raw"].get("path") or "").lower()]
            if rows:
                result.signals.append(self._text_signal(
                    ind, rows, "ioc.url_marker_match",
                    f"IoC-listed marker {ind.value!r} in requested URLs",
                    sorted({r["raw"].get("path", "")[:200] for r in rows})))

        result.metrics.append(Metric(
            key="ioc.indicators", value=len(iocs.indicators), section="general",
            label="IoC list indicators checked"))
        result.metrics.append(Metric(
            key="ioc.matched", value=len(result.signals), section="general",
            label="IoC list indicators seen"))
        return result

    # ----- signals ---------------------------------------------------------- #

    def _ip_signal(self, ind: Indicator, values: set[str], traffic: list[dict[str, Any]],
                   profile: Profile) -> Signal | None:
        rows = [r for r in traffic if r["src_ip"] in values or r["dst_ip"] in values]
        if not rows:
            return None
        inbound = [r for r in rows if r["src_ip"] in values]
        outbound = [r for r in rows if r["dst_ip"] in values and r["src_ip"] not in values]
        accepted_in = sum(r["hits"] for r in inbound if _allowed(r))
        blocked_in = sum(r["hits"] for r in inbound if not _allowed(r))
        out_allowed = sum(r["hits"] for r in outbound if _allowed(r))
        out_blocked = sum(r["hits"] for r in outbound if not _allowed(r))

        severity = ind.severity
        only_blocked_inbound = not outbound and accepted_in == 0
        if only_blocked_inbound:
            severity = min(severity, Severity.LOW)

        local = {r["dst_ip"] for r in inbound} | {r["src_ip"] for r in outbound}
        internal = sorted(ip for ip in local if ip and ip not in values)
        ports = Counter()
        for r in rows:
            if r["dst_port"] is not None:
                ports[r["dst_port"]] += r["hits"]
        if outbound:
            what = "contacted by an internal host"
        elif accepted_in:
            what = "connected in and was accepted"
        else:
            what = "probed the network, all blocked"
        evidence: dict[str, Any] = {
            **ind.to_evidence(),
            "matched": sorted(values)[:_MAX_LISTED],
            "inbound_accepted": accepted_in,
            "inbound_blocked": blocked_in,
            "outbound_allowed": out_allowed,
            "outbound_blocked": out_blocked,
            "dst_ports": [p for p, _ in ports.most_common(_MAX_LISTED)],
            "local_addresses": [{"ip": ip, "zone": profile.zone_of(ip)}
                                for ip in internal[:_MAX_LISTED]],
            "first_seen": _ts(min(r["first"] for r in rows if r["first"])),
            "last_seen": _ts(max(r["last"] for r in rows if r["last"])),
        }
        if only_blocked_inbound and severity < ind.severity:
            evidence["severity_note"] = (f"list severity {ind.severity.label()} capped at "
                                         f"LOW: inbound only, every packet blocked")
        entities = [Entity(EntityType.IP, v, "indicator") for v in sorted(values)[:_MAX_LISTED]]
        entities += [Entity(EntityType.IP, ip, "local") for ip in internal[:_MAX_LISTED]]
        return Signal(
            id=f"ioc.{ind.kind}.{ind.value}",
            analyzer=self.name,
            title=f"IoC-listed address {ind.value} {what}",
            taxonomy="ioc.ip_match",
            severity_hint=severity,
            confidence=_TIER_CONFIDENCE.get(ind.tier, 0.5),
            entities=entities,
            evidence=evidence,
            narrative_hint=_hint(ind, outbound=bool(outbound), accepted=accepted_in > 0),
        )

    def _text_signal(self, ind: Indicator, rows: list[dict[str, Any]], taxonomy: str,
                     title: str, matched: list[str]) -> Signal:
        clients = sorted({r["src_ip"] for r in rows if r.get("src_ip")})
        statuses = Counter(r["action"] for r in rows if r.get("action"))
        evidence: dict[str, Any] = {
            **ind.to_evidence(),
            "matched": matched[:_MAX_LISTED],
            "events": len(rows),
            "clients": clients[:_MAX_LISTED],
            "where": sorted({r["device"] for r in rows if r.get("device")})[:_MAX_LISTED],
            "sites": sorted({r["domain"] for r in rows
                             if r.get("domain") and r["kind"] == "http"})[:_MAX_LISTED],
            "principals": sorted({r["user"] for r in rows if r.get("user")})[:_MAX_LISTED],
            "responses": dict(statuses.most_common(_MAX_LISTED)),
            "first_seen": _ts(rows[0]["ts"]),
            "last_seen": _ts(rows[-1]["ts"]),
        }
        entities = [Entity(EntityType.IP, c, "client") for c in clients[:_MAX_LISTED]]
        return Signal(
            id=f"ioc.{ind.kind}.{ind.value}"[:255], analyzer=self.name, title=title[:200],
            taxonomy=taxonomy, severity_hint=ind.severity,
            confidence=_TIER_CONFIDENCE.get(ind.tier, 0.5), entities=entities,
            evidence=evidence,
            narrative_hint=(
                "Matched a published indicator list's tool fingerprint; its warning is in "
                "evidence.warning. A user agent or URL marker is set by the client, so it "
                "is easy to fake or rename - weigh it with what the same clients did: "
                "check responses (2xx means the server answered), and what else those "
                "addresses requested or called."),
        )

    def _domain_signal(self, ind: Indicator, values: set[str],
                       lookups: list[dict[str, Any]]) -> Signal | None:
        rows = [r for r in lookups if r["domain"] in values]
        if not rows:
            return None
        clients = sorted({r["client_ip"] for r in rows if r["client_ip"]})
        queries = sum(r["queries"] for r in rows)
        blocked = sum(r["blocked"] for r in rows)
        evidence: dict[str, Any] = {
            **ind.to_evidence(),
            "matched": sorted(values)[:_MAX_LISTED],
            "queries": queries,
            "blocked_by_resolver": blocked,
            "clients": clients[:_MAX_LISTED],
            "first_seen": _ts(min(r["first"] for r in rows if r["first"])),
            "last_seen": _ts(max(r["last"] for r in rows if r["last"])),
        }
        entities = [Entity(EntityType.DOMAIN, v, "indicator") for v in sorted(values)[:_MAX_LISTED]]
        entities += [Entity(EntityType.IP, c, "client") for c in clients[:_MAX_LISTED]]
        return Signal(
            id=f"ioc.{ind.kind}.{ind.value}",
            analyzer=self.name,
            title=f"IoC-listed domain {ind.value} looked up by {len(clients)} client(s)",
            taxonomy="ioc.domain_match",
            severity_hint=ind.severity,
            confidence=_TIER_CONFIDENCE.get(ind.tier, 0.5),
            entities=entities,
            evidence=evidence,
            narrative_hint=_hint(ind, outbound=True, accepted=blocked < queries),
        )


def _allowed(row: dict[str, Any]) -> bool:
    action = (row.get("action") or "").lower()
    return action not in _BLOCKED


def _ts(dt) -> str | None:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else None


def _hint(ind: Indicator, *, outbound: bool, accepted: bool) -> str:
    parts = ["Matched a published indicator list; the list's own warning is in "
             "evidence.warning."]
    if ind.tier == "T4":
        parts.append("The list marks this tier as never actionable on its own: report it "
                     "only alongside other evidence about the same host.")
    elif ind.tier == "T3":
        parts.append("Past-incident infrastructure that may since have been reassigned: "
                     "correlate before calling it hostile.")
    if outbound:
        parts.append("An internal host initiated this contact, which matters far more than "
                     "inbound scanning: identify the host and what else it talked to.")
    elif accepted:
        parts.append("Some inbound traffic was accepted: check what service answered.")
    else:
        parts.append("Every inbound packet was blocked, so this is a closed-door probe.")
    return " ".join(parts)
