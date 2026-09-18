"""New-device detection: an internal IP - or a MAC address - making its
first-ever appearance.

Reuses the same novelty mechanism `dns_anomalies.py` already applies to
domains - `Baseline.novel()` against the entities table - for two different
identities:

  * `EntityType.IP` - internal client/source IPs. Every event already feeds
    the entities table via `store.entity_pairs_from_events()` (bumping
    `EntityType.IP` for every `src_ip`/`client_ip`), so a device's first-ever
    appearance is already recorded before this analyzer ever runs.
  * `EntityType.DEVICE` - MAC addresses, sourced from DHCP lease lines and
    Wi-Fi deauthentication events (`Event.user`, set in `librenms_syslog.py`).
    A MAC survives DHCP lease renewal where an IP does not, so it catches
    "genuinely new device" without re-flagging an existing device every time
    its lease renews to a fresh address - and without needing any dedicated
    persistence of its own. `Event.user` also carries a Windows account name
    on logon events now (see `auth_activity.py`), so candidates here are
    shape-validated as MACs before being treated as one.

This is why a device behind a NAT-gated segment (no SNMP inventory, no local
DNS resolver) still gets caught here even though it never appears in the
curated device directory (`devices.py`): the entity table is fed straight
from firewall SRC=/DST=, DNS client_ip, and DHCP/deauth MAC fields, not from
any per-source device list.
"""

from __future__ import annotations

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

UNTRUSTED = {"untrusted", "semi-trusted", "dmz", "guest"}
MAX_CANDIDATES = 500
MAX_REPORTED_PER_ZONE = 15
MAC_MAX_REPORTED = 20

#: `Event.user` is overloaded across sources/kinds (a MAC on DHCP/deauth
#: lines, a Windows account name on logon events - see auth_activity.py) so
#: the MAC-novelty check below must validate shape before treating a value as
#: a device identity, not just assume every `user` on these kinds is a MAC.
_MAC_SHAPE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class NovelClientAnalyzer(Analyzer):
    name = "novel_clients"
    requires_kinds = frozenset({EventKind.DNS, EventKind.FIREWALL, EventKind.SYSTEM,
                               EventKind.AUTH})
    order = 35

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        if not baseline.has_baseline():
            r.notes.append(
                "first run with data - every internal client is nominally new, "
                "so device novelty is not reported as a signal this time"
            )
            return r

        self._novel_ips(q, r, profile, baseline)
        self._novel_macs(q, r, baseline)
        return r

    def _novel_ips(self, q: EventQuery, r: AnalyzerResult,
                   profile: Profile, baseline: Baseline) -> None:
        candidates: set[str] = set()
        for ip, _n in q.top("src_ip", n=MAX_CANDIDATES, kind=EventKind.FIREWALL):
            if ip and profile.is_internal(ip):
                candidates.add(ip)
        for ip, _n, _blk in q.dns_client_stats(n=MAX_CANDIDATES):
            if ip and profile.is_internal(ip):
                candidates.add(ip)
        if not candidates:
            return

        novel = baseline.novel(EntityType.IP, sorted(candidates))
        if not novel:
            return

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

    def _novel_macs(self, q: EventQuery, r: AnalyzerResult, baseline: Baseline) -> None:
        """MAC-based novelty, independent of the IP-based check above: a MAC
        survives DHCP lease renewal, so this catches a genuinely new device
        without re-flagging an existing one every time its lease renews to a
        fresh address - the false-positive case the IP-only check cannot
        avoid on its own.
        """
        macs = {
            m for m, _n in q.top("user", n=MAX_CANDIDATES,
                                 kind=[str(EventKind.SYSTEM), str(EventKind.AUTH)])
            if m and _MAC_SHAPE.match(m)
        }
        if not macs:
            return
        novel = baseline.novel(EntityType.DEVICE, sorted(macs))
        if not novel:
            return

        shown = sorted(novel)[:MAC_MAX_REPORTED]
        r.signals.append(Signal(
            id="net.novel_device_mac",
            analyzer=self.name,
            title=f"{len(novel)} new device identity (MAC) seen for the first time",
            taxonomy="net.novel_device_mac",
            severity_hint=Severity.LOW,
            confidence=0.5,
            entities=[Entity(type=EntityType.HOST, value=mac, role="client") for mac in shown],
            evidence={"count": len(novel), "macs": shown},
            narrative_hint=(
                "Tracked by MAC address, not IP - this will not re-flag a device "
                "that simply renewed its DHCP lease to a new address. A genuinely "
                "new MAC is the same 'new device' fact as the IP-based signal "
                "above, just immune to IP churn."
            ),
        ))
