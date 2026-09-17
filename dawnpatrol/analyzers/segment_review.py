"""Per-zone review driven entirely by the site profile.

Nothing here knows what an "IoT segment" is. Zones, their trust level, their
gateways, and their expected egress all come from profile.yml, so the same code
reviews any network.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..models import (
    UTC,
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

#: Coarse time-of-day buckets in the site's own timezone (profile.yml's
#: `site.timezone`) - fine enough to catch "active when normally quiet",
#: coarse enough that four metrics per zone per run is a modest, worthwhile
#: amount of new history to persist, not an hourly-resolution row explosion.
_DAYPARTS = (
    ("night", range(0, 6)),
    ("morning", range(6, 12)),
    ("afternoon", range(12, 18)),
    ("evening", range(18, 24)),
)
DAYPART_HISTORY_DAYS = 30
DAYPART_MIN_HISTORY = 5
DAYPART_QUIET_CEILING = 5.0
DAYPART_MIN_THIS_RUN = 20
DAYPART_MULTIPLE = 4.0


def _site_timezone(tz_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


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

            # Distinct client population, straight from the traffic itself - not
            # from any curated device inventory. A segment behind a NAT gateway
            # (no SNMP device list, no local DNS resolver) can still show a real
            # client count here, because the firewall log's own SRC=/DST= fields
            # carry the client's private IP even when the gateway masks it on
            # the way out to the WAN. Counted on both sides deliberately: many
            # firewalls only log denied traffic, and a device that only ever
            # appears as the target of a rejected inbound session (dst_zone)
            # would otherwise never be counted at all.
            dns_clients = q.distinct_count("client_ip", kind=EventKind.DNS, src_zone=zone.name)
            fw_clients = len(
                set(q.distinct_values("src_ip", kind=EventKind.FIREWALL, src_zone=zone.name))
                | set(q.distinct_values("dst_ip", kind=EventKind.FIREWALL, dst_zone=zone.name))
            )
            r.metrics.append(Metric(
                key=f"zone.{zone.name}.dns_clients", value=dns_clients, section="segments",
                label=f"{zone.name}: distinct DNS clients",
            ))
            r.metrics.append(Metric(
                key=f"zone.{zone.name}.fw_clients", value=fw_clients, section="segments",
                label=f"{zone.name}: distinct firewall sources",
            ))

            if zone.expected_egress_domains and dns_count:
                self._unexpected_egress(q, r, profile, zone)
            # Untrusted zones: any accepted inbound is notable outright. Trusted
            # zones very often have a standing, intentional port-forward, so the
            # same blanket rule there would be constant noise - only a genuinely
            # new external source reaching it is worth a signal.
            self._inbound_to_zone(q, r, profile, zone, baseline,
                                  require_novel=zone.trust not in UNTRUSTED)
            self._time_of_day(q, r, profile, baseline, zone)

        self._nat_notes(r, profile)
        return r

    # ----- egress outside the expected set ----------------------------------- #

    def _unexpected_egress(self, q: EventQuery, r: AnalyzerResult,
                           profile: Profile, zone) -> None:
        patterns = [p.lower().lstrip("*.") for p in zone.expected_egress_domains]
        unexpected: list[tuple[str, int]] = []
        for domain, _count, _blk in q.dns_domain_stats(n=2000):
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

    def _inbound_to_zone(self, q: EventQuery, r: AnalyzerResult, profile: Profile,
                         zone, baseline: Baseline, require_novel: bool = False) -> None:
        """Accepted inbound sessions reaching this zone from outside.

        ``require_novel`` narrows this to sources never seen reaching this
        zone before - novelty is tracked per source IP only, not per
        (source, port) pair, so a known peer hitting a new port on the same
        zone will not itself trigger this. Used for trusted zones, where a
        standing, intentional port-forward is common and would otherwise fire
        on every run; untrusted zones keep the original any-inbound rule.
        """
        accepted = q.group_pairs("src_ip", "dst_port", n=50,
                                 kind=EventKind.FIREWALL, action="accept",
                                 dst_zone=zone.name)
        external = [
            (src, port, count) for src, port, count in accepted
            if src and profile.is_external(src)
        ]
        if not external:
            return

        if require_novel:
            if not baseline.has_baseline():
                return  # everything looks "new" on a first run; too noisy to report
            novel_sources = set(baseline.novel(
                EntityType.IP, sorted({s for s, _p, _c in external})
            ))
            external = [x for x in external if x[0] in novel_sources]
            if not external:
                return

        watched = set(profile.policy.attack_surface_ports)
        notable = [x for x in external if x[1] in watched] or external
        severity = Severity.MEDIUM if require_novel else Severity.HIGH
        title = (f"New external source accepted inbound into {zone.name}" if require_novel
                else f"Inbound external sessions accepted into {zone.name}")
        r.signals.append(Signal(
            id=f"zone.{zone.name}.inbound_accepted",
            analyzer=self.name,
            title=title,
            taxonomy="segment.inbound_accepted",
            severity_hint=severity,
            confidence=0.6 if require_novel else 0.8,
            entities=(
                [Entity(type=EntityType.IP, value=s, role="source") for s, _, _ in notable[:8]]
                + [Entity(type=EntityType.PORT, value=str(p), role="destination")
                   for _, p, _ in notable[:8] if p]
            ),
            evidence={
                "zone": zone.name,
                "trust": zone.trust,
                "novel_sources_only": require_novel,
                "accepted": [{"src": s, "dst_port": p, "hits": n} for s, p, n in notable[:20]],
            },
            narrative_hint=(
                "A trusted zone often has a known, standing port-forward (a game "
                "server, remote access tool); this fires only for a source address "
                "that has never reached this zone before - a familiar port-forward's "
                "peers churning is expected, a brand-new one appearing is not."
            ) if require_novel else (
                "An accepted inbound session into a low-trust segment is materially "
                "different from a dropped probe. Confirm it corresponds to an "
                "intentional port-forward before treating it as an incident - and "
                "confirm the reverse before dismissing it."
            ),
        ))

    # ----- time-of-day baselining ---------------------------------------------- #

    def _time_of_day(self, q: EventQuery, r: AnalyzerResult,
                     profile: Profile, baseline: Baseline, zone) -> None:
        """Flag activity during hours that are historically quiet for this zone.

        A volume spike (firewall_volume.py) and a shift in *when* things
        happen are different signatures: a zone that is reliably silent
        00:00-06:00 seeing real traffic there is notable independent of
        whether the total volume for the day looks unremarkable. Needs
        several days of its own history to mean anything, so it is silent
        (not absent - the metric is still recorded, building that history)
        until enough has accumulated.
        """
        tz = _site_timezone(profile.timezone)
        hourly = q.hourly(kind=EventKind.FIREWALL, src_zone=zone.name)

        # Recorded even when this zone had zero firewall traffic this run - a
        # real, meaningful "0" for its history, not an absence of data.
        by_daypart: dict[str, int] = {name: 0 for name, _hours in _DAYPARTS}
        for bucket, count in hourly.items():
            try:
                dt = datetime.strptime(bucket, "%Y-%m-%d %H:00").replace(tzinfo=UTC)
            except ValueError:
                continue
            local_hour = dt.astimezone(tz).hour
            for name, hours in _DAYPARTS:
                if local_hour in hours:
                    by_daypart[name] += count
                    break

        for name, count in by_daypart.items():
            key = f"zone.{zone.name}.daypart.{name}"
            r.metrics.append(Metric(key=key, value=count, section="segments_time",
                                    label=f"{zone.name} {name} firewall events"))

            history = [pt["value"] for pt in baseline.series(key, days=DAYPART_HISTORY_DAYS)
                      if isinstance(pt["value"], (int, float))]
            if len(history) < DAYPART_MIN_HISTORY:
                continue
            hist_mean = statistics.fmean(history)
            if hist_mean > DAYPART_QUIET_CEILING:
                continue  # not a historically-quiet daypart for this zone
            if count < DAYPART_MIN_THIS_RUN or count < max(hist_mean, 1.0) * DAYPART_MULTIPLE:
                continue

            severity = Severity.MEDIUM if zone.trust in UNTRUSTED else Severity.LOW
            r.signals.append(Signal(
                id=f"zone.{zone.name}.daypart_anomaly.{name}",
                analyzer=self.name,
                title=f"{zone.name} was active during its normally-quiet {name} hours",
                taxonomy="segment.time_of_day_anomaly",
                severity_hint=severity,
                confidence=0.5,
                entities=[Entity(type=EntityType.HOST, value=zone.name, role="segment")],
                evidence={
                    "zone": zone.name,
                    "daypart": name,
                    "events_this_run": count,
                    "historical_mean": round(hist_mean, 1),
                    "history_days_observed": len(history),
                    "site_timezone": profile.timezone,
                },
                narrative_hint=(
                    f"This zone is historically quiet during {name} hours (site "
                    f"timezone, {profile.timezone}). A shift in *when* activity "
                    f"happens is distinct from a volume spike - check what "
                    f"specifically ran during this window before treating it as "
                    f"routine."
                ),
            ))

    # ----- attribution limits ---------------------------------------------------- #

    def _nat_notes(self, r: AnalyzerResult, profile: Profile) -> None:
        for gateway in profile.policy.nat_attribution_limited_behind:
            caveat = profile.attribution_caveat(gateway)
            if caveat:
                r.notes.append(caveat)
