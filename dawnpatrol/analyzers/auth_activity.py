"""Authentication-adjacent event analysis: VPN service activity and Wi-Fi
device deauthentication.

VPN: in production, this deployment's OpenVPN daemon only ever forwards
lifecycle lines - startup, TUN/TAP interface up/down, SIGTERM - never a
per-session "peer authenticated" line (verified against 90 days / ~950k real
syslog lines: every VPNSERVER1 entry is daemon lifecycle noise). So there is
no per-user VPN login data to analyze here yet. What this file does with VPN
events is therefore limited to a restart/reconnect-frequency metric, clearly
labelled as such - never presented as session or login analysis it has no
data to support. If a deployment's OpenVPN log verbosity is raised enough to
forward real CLIENT_CONNECT/peer lines, this is the natural place to add
per-session analysis once `librenms_syslog.py` parses them into structured
fields.

Device authentication: 802.11 deauthentication events (`WLCEVENTD`/`HOSTAPD`,
reclassified to `EventKind.AUTH` with the client MAC in `Event.user` by
`librenms_syslog.py`) are genuine, present, device-authentication evidence.
Two checks here: one device deauthenticating far more than its peers
(flapping radio, interference, or a targeted deauth attack against that one
client), and a mass-deauth burst across many distinct devices in a short
window (the signature of a deauthentication-flood attack against the AP
itself, not any one client).
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta

from ..models import UTC, AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from .base import Analyzer
from .baseline import Baseline

#: Programs whose AUTH events are VPN-daemon lifecycle noise, not sessions.
_VPN_EXACT = {"OPENVPN", "SSHD", "PPTPD"}
_VPN_RESTART_MULTIPLE = 3.0
_VPN_RESTART_FLOOR = 30

_DEAUTH_MIN_TOTAL = 20
_DEAUTH_OUTLIER_MULTIPLE = 4.0
_DEAUTH_OUTLIER_FLOOR = 10
_MASS_DEAUTH_WINDOW = timedelta(minutes=5)
_MASS_DEAUTH_MIN_DISTINCT_MACS = 6
_SAMPLE_LIMIT = 4000


class AuthActivityAnalyzer(Analyzer):
    name = "auth_activity"
    requires_kinds = frozenset({EventKind.AUTH})
    order = 45

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        self._vpn(q, r, baseline)
        self._deauth(q, r)
        return r

    # ----- VPN: service-level only, no per-session data available ------------- #

    def _vpn(self, q: EventQuery, r: AnalyzerResult, baseline: Baseline) -> None:
        programs = q.distinct_values("program", kind=EventKind.AUTH)
        vpn_programs = [p for p in programs
                        if p and (p.upper().startswith("VPNSERVER") or p.upper() in _VPN_EXACT)]
        if not vpn_programs:
            return
        total = q.count(kind=EventKind.AUTH, program=vpn_programs)
        if not total:
            return

        r.metrics.append(Metric(
            key="auth.vpn_events", value=total, section="router",
            label="VPN daemon events (lifecycle, not sessions)",
            prior=baseline.prior("auth.vpn_events"),
        ))
        r.notes.append(
            f"{total} VPN daemon syslog line(s) this run - lifecycle events "
            f"(startup/shutdown/interface changes), not per-session logins. "
            f"This deployment's VPN log does not forward peer/user "
            f"authentication lines, so per-login VPN analysis is not possible "
            f"from this data source yet."
        )

        prior = baseline.prior("auth.vpn_events")
        if prior and prior > 0 and total >= prior * _VPN_RESTART_MULTIPLE \
                and total >= _VPN_RESTART_FLOOR:
            r.signals.append(Signal(
                id="auth.vpn_restart_frequency",
                analyzer=self.name,
                title="VPN daemon logged unusually many lifecycle events this run",
                taxonomy="auth.vpn_instability",
                severity_hint=Severity.LOW,
                confidence=0.4,
                entities=[Entity(type=EntityType.HOST, value="vpn-daemon", role="service")],
                evidence={"events_this_run": total, "prior_run_events": prior},
                narrative_hint=(
                    "This counts daemon lifecycle lines (startup/shutdown), not "
                    "logins - this deployment does not forward per-session VPN "
                    "authentication data. Frequent restarts point to instability "
                    "(crash-looping, a flaky WAN link, a config change) rather "
                    "than unauthorized access attempts, which this data cannot "
                    "speak to either way."
                ),
            ))

    # ----- Wi-Fi deauthentication: real device-auth evidence ------------------ #

    def _deauth(self, q: EventQuery, r: AnalyzerResult) -> None:
        auth_deauth = {"kind": EventKind.AUTH, "action": "deauth"}
        total = q.count(**auth_deauth)
        if not total:
            return
        distinct_macs = q.distinct_count("user", **auth_deauth)
        r.metrics.append(Metric(key="auth.deauth_total", value=total, section="router",
                                label="Wi-Fi deauthentication events"))
        r.metrics.append(Metric(key="auth.deauth_distinct_devices", value=distinct_macs,
                                section="router", label="Distinct devices deauthenticated"))

        self._per_device_outlier(q, r, total)
        self._mass_deauth_burst(q, r)

    def _per_device_outlier(self, q: EventQuery, r: AnalyzerResult, total: int) -> None:
        per_mac = q.top("user", n=100, kind=EventKind.AUTH, action="deauth")
        if len(per_mac) < 2 or total < _DEAUTH_MIN_TOTAL:
            return
        # Compare the top device against its peers' median, excluding itself -
        # otherwise the very outlier being tested for pulls its own baseline up.
        top_mac, top_count = per_mac[0]
        peer_median = statistics.median(c for _m, c in per_mac[1:])
        if top_count < max(_DEAUTH_OUTLIER_FLOOR, (peer_median + 1) * _DEAUTH_OUTLIER_MULTIPLE):
            return
        r.signals.append(Signal(
            id=f"auth.deauth_outlier.{top_mac}",
            analyzer=self.name,
            title=f"Device {top_mac} deauthenticated far more than its peers",
            taxonomy="auth.deauth_outlier",
            severity_hint=Severity.LOW,
            confidence=0.5,
            entities=[Entity(type=EntityType.HOST, value=top_mac, role="client")],
            evidence={
                "mac": top_mac, "deauth_count": top_count,
                "peer_median_deauths": peer_median,
                "distinct_devices_this_run": len(per_mac),
            },
            narrative_hint=(
                "Repeated deauthentication for one device is usually Wi-Fi "
                "instability - weak signal, interference, a failing radio - "
                "but a targeted deauth attack against that one client produces "
                "the identical shape. Check reason codes and RSSI in the raw "
                "message before concluding either way; this signal cannot "
                "distinguish them on its own."
            ),
        ))

    def _mass_deauth_burst(self, q: EventQuery, r: AnalyzerResult) -> None:
        rows = q.sample(n=_SAMPLE_LIMIT, kind=EventKind.AUTH, action="deauth")
        events: list[tuple[datetime, str]] = []
        for row in rows:
            ts, mac = row.get("ts"), row.get("user")
            if not ts or not mac:
                continue
            try:
                dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                continue
            events.append((dt, mac))
        if len(events) < _MASS_DEAUTH_MIN_DISTINCT_MACS:
            return
        events.sort(key=lambda e: e[0])

        # Sliding window: the widest set of distinct MACs deauthenticated
        # within any _MASS_DEAUTH_WINDOW-wide span.
        left = 0
        counts: dict[str, int] = {}
        best_macs: set[str] = set()
        best_start = events[0][0]
        for ts, mac in events:
            counts[mac] = counts.get(mac, 0) + 1
            while ts - events[left][0] > _MASS_DEAUTH_WINDOW:
                left_mac = events[left][1]
                counts[left_mac] -= 1
                if counts[left_mac] == 0:
                    del counts[left_mac]
                left += 1
            if len(counts) > len(best_macs):
                best_macs = set(counts)
                best_start = events[left][0]

        if len(best_macs) < _MASS_DEAUTH_MIN_DISTINCT_MACS:
            return
        r.signals.append(Signal(
            id=f"auth.mass_deauth.{best_start.strftime('%Y%m%dT%H%M%S')}",
            analyzer=self.name,
            title=(f"{len(best_macs)} distinct devices deauthenticated within "
                  f"{int(_MASS_DEAUTH_WINDOW.total_seconds() // 60)} minutes"),
            taxonomy="auth.mass_deauth_burst",
            severity_hint=Severity.MEDIUM,
            confidence=0.55,
            entities=[Entity(type=EntityType.HOST, value=mac, role="client")
                     for mac in sorted(best_macs)[:10]],
            evidence={
                "window_start": best_start.isoformat(),
                "window_minutes": int(_MASS_DEAUTH_WINDOW.total_seconds() // 60),
                "distinct_devices": len(best_macs),
                "macs": sorted(best_macs)[:20],
            },
            narrative_hint=(
                "Many different devices deauthenticating in a short window is "
                "the signature of a deauth-flood attack against the access "
                "point itself, not any one client - but it is also what an AP "
                "reboot, a channel change, or a firmware update looks like. "
                "Correlate with router restarts or config changes before "
                "treating this as an attack."
            ),
        ))
