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

Windows endpoint telemetry: any device forwarding Windows Security auditing
to this deployment's syslog collector (confirmed live against device 8,
`10.128.15.135`) gets real per-account logon evidence -
`librenms_syslog._parse_windows_security_audit` turns the rendered event text
into `EventKind.AUTH` with `user` as the account and `proto` repurposed to
carry the logon type (interactive/network/rdp/service/...). Four checks:
a never-seen-before account authenticating on the host, a successful logon
whose source address is outside this network, a burst of logon failures
(structurally ready, unverified against real data - none have occurred on
device 8 yet), and a Windows Defender detection (`EventKind.IDS`, the first
consumer of that kind) - which is near-binary in value, since the source only
emits it outside its routine health-heartbeat template when something was
actually flagged.

Linux SSH: classic OpenSSH auth lines - "Accepted"/"Failed"/"Invalid user",
unchanged in format across decades of versions - confirmed live against
device 6 (this session's own Fedora host), which produces ~150k syslog
lines/day, 63% of it `AUDIT type=BPF` noise this file deliberately does not
touch. `librenms_syslog._parse_sshd_session` turns the auth-outcome lines
into the same `EventKind.AUTH` shape as Windows logons (`user` = account,
`proto` = auth method). Three checks, symmetric to the Windows ones: a new
account authenticating over SSH, a successful logon from outside this
network, and a burst of failed/invalid-user attempts - the single most
standard brute-force signature there is, though none had occurred on this
device as of when this was built.
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
#: SSHD is deliberately excluded - it has real per-session parsing now (see
#: librenms_syslog._parse_sshd_session and _ssh_logons below); counting it
#: here too would double-count the same events under two metrics.
_VPN_EXACT = {"OPENVPN", "PPTPD"}
_VPN_RESTART_MULTIPLE = 3.0
_VPN_RESTART_FLOOR = 30

_DEAUTH_MIN_TOTAL = 20
_DEAUTH_OUTLIER_MULTIPLE = 4.0
_DEAUTH_OUTLIER_FLOOR = 10
_MASS_DEAUTH_WINDOW = timedelta(minutes=5)
_MASS_DEAUTH_MIN_DISTINCT_MACS = 6
_SAMPLE_LIMIT = 4000

#: Keep in sync with librenms_syslog._parse_windows_security_audit's `action`
#: values and store.py's _ACCOUNT_LOGON_ACTIONS.
_WINDOWS_LOGON_ACTIONS = ["logon_success", "logon_failed", "privileged",
                         "explicit_creds", "lockout"]
#: Logon types that carry a real source address - see _WIN_LOGON_TYPES in
#: librenms_syslog.py. "service"/"batch"/"unlock"/"cached" are local, not
#: remote, and never populate Source Network Address anyway.
_REMOTE_LOGON_TYPES = {"network", "rdp", "net_clear"}
_LOGON_FAILURE_BURST_MIN = 5
_WINDOWS_SAMPLE_LIMIT = 500

#: Keep in sync with librenms_syslog._parse_sshd_session's `action` values.
_SSH_AUTH_ACTIONS = ["ssh_accepted", "ssh_failed", "ssh_invalid"]
_SSH_FAILURE_ACTIONS = ["ssh_failed", "ssh_invalid"]
_SSH_FAILURE_BURST_MIN = 5
_SSH_SAMPLE_LIMIT = 500


class AuthActivityAnalyzer(Analyzer):
    name = "auth_activity"
    requires_kinds = frozenset({EventKind.AUTH, EventKind.IDS})
    order = 45

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        self._vpn(q, r, baseline)
        self._deauth(q, r)
        self._windows_logons(q, r, baseline, profile)
        self._windows_defender(q, r)
        self._ssh_logons(q, r, baseline, profile)
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

    # ----- Windows endpoint: real per-account logon evidence ------------------ #

    def _windows_logons(self, q: EventQuery, r: AnalyzerResult,
                        baseline: Baseline, profile: Profile) -> None:
        total = q.count(kind=EventKind.AUTH, action=_WINDOWS_LOGON_ACTIONS)
        if not total:
            return
        r.metrics.append(Metric(
            key="auth.windows_logon_events", value=total, section="router",
            label="Windows logon/audit events",
        ))
        self._windows_new_account(q, r, baseline)
        self._windows_remote_logon(q, r, profile)
        self._windows_logon_failures(q, r)

    def _windows_new_account(self, q: EventQuery, r: AnalyzerResult,
                             baseline: Baseline) -> None:
        if not baseline.has_baseline():
            return
        accounts = {a for a in q.distinct_values("user", kind=EventKind.AUTH,
                                                  action=_WINDOWS_LOGON_ACTIONS) if a}
        novel = baseline.novel(EntityType.USER, sorted(accounts))
        if not novel:
            return
        r.signals.append(Signal(
            id="auth.windows_new_account",
            analyzer=self.name,
            title=f"{len(novel)} account(s) logged on to a Windows host for the first time",
            taxonomy="auth.windows_new_account",
            severity_hint=Severity.MEDIUM,
            confidence=0.55,
            entities=[Entity(type=EntityType.USER, value=a, role="account")
                     for a in sorted(novel)[:10]],
            evidence={"accounts": sorted(novel)[:20]},
            narrative_hint=(
                "A never-seen-before account authenticating is routine the first "
                "time this analyzer ever runs against a device, and routine "
                "again for a legitimate new service or user account - but on a "
                "single-purpose or single-user host it is exactly what an "
                "unauthorized local account would look like too. Check whether "
                "this account is expected before dismissing it."
            ),
        ))

    def _windows_remote_logon(self, q: EventQuery, r: AnalyzerResult,
                              profile: Profile) -> None:
        rows = q.sample(n=_WINDOWS_SAMPLE_LIMIT, kind=EventKind.AUTH, action="logon_success")
        external: dict[str, dict] = {}
        for row in rows:
            src_ip, logon_type = row.get("src_ip"), row.get("proto")
            if not src_ip or logon_type not in _REMOTE_LOGON_TYPES:
                continue
            if profile.is_internal(src_ip):
                continue
            external.setdefault(src_ip, row)
        for src_ip, row in sorted(external.items()):
            r.signals.append(Signal(
                id=f"auth.windows_external_logon.{src_ip}",
                analyzer=self.name,
                title=f"Windows logon accepted from external address {src_ip}",
                taxonomy="auth.windows_external_logon",
                severity_hint=Severity.HIGH,
                confidence=0.7,
                entities=[
                    Entity(type=EntityType.IP, value=src_ip, role="source"),
                    Entity(type=EntityType.USER, value=row.get("user") or "unknown",
                          role="account"),
                ],
                evidence={
                    "src_ip": src_ip, "account": row.get("user"),
                    "logon_type": row.get("proto"), "device": row.get("device"),
                },
                narrative_hint=(
                    "A successful Windows logon whose source address is outside "
                    "this network is either an authorised remote-access path (a "
                    "VPN terminating locally before RDP, a jump host) or a "
                    "genuinely external logon reaching this host directly - "
                    "confirm which before treating it as routine. Unlike "
                    "perimeter scanning, this has no innocent default "
                    "explanation."
                ),
            ))

    def _windows_logon_failures(self, q: EventQuery, r: AnalyzerResult) -> None:
        """Structurally ready, not yet verified against real data - no failed
        Windows logon has occurred on any forwarding device so far. Reporting
        that plainly (by simply not firing) is correct; this exists for the
        day it does."""
        total = q.count(kind=EventKind.AUTH, action="logon_failed")
        if total < _LOGON_FAILURE_BURST_MIN:
            return
        by_account = q.top("user", n=10, kind=EventKind.AUTH, action="logon_failed")
        r.signals.append(Signal(
            id="auth.windows_logon_failure_burst",
            analyzer=self.name,
            title=f"{total} failed Windows logon(s) this run",
            taxonomy="auth.windows_logon_failure_burst",
            severity_hint=Severity.MEDIUM,
            confidence=0.5,
            entities=[Entity(type=EntityType.USER, value=a, role="account")
                     for a, _n in by_account],
            evidence={"failed_logons": total, "by_account": by_account},
            narrative_hint=(
                "A cluster of failed Windows logons is the shape of a "
                "brute-force or password-spray attempt, but is also what a "
                "stale saved credential or a mistyped password produces. Check "
                "whether failures concentrate on one account (targeted) or "
                "spread across many (spray), and whether a later logon from "
                "the same source succeeded."
            ),
        ))

    # ----- Windows endpoint: AV detections -------------------------------------- #

    def _windows_defender(self, q: EventQuery, r: AnalyzerResult) -> None:
        total = q.count(kind=EventKind.IDS, action="detection")
        if not total:
            return
        samples = q.sample(n=5, kind=EventKind.IDS, action="detection")
        r.signals.append(Signal(
            id="endpoint.defender_detection",
            analyzer=self.name,
            title=f"Windows Defender reported {total} detection event(s)",
            taxonomy="endpoint.malware_detection",
            severity_hint=Severity.HIGH,
            confidence=0.75,
            entities=[Entity(type=EntityType.HOST, value=row.get("device") or "unknown",
                            role="host") for row in samples],
            evidence={
                "count": total,
                "messages": [(row.get("message") or "")[:300] for row in samples],
            },
            narrative_hint=(
                "Windows Defender does not raise this outside its routine "
                "health-heartbeat template unless it actually detected "
                "something. Confirm what was flagged, whether it was removed "
                "or only quarantined, and whether the same host shows any "
                "other unusual activity this run."
            ),
        ))

    # ----- Linux SSH: real per-account, per-source auth evidence --------------- #

    def _ssh_logons(self, q: EventQuery, r: AnalyzerResult,
                    baseline: Baseline, profile: Profile) -> None:
        total = q.count(kind=EventKind.AUTH, action=_SSH_AUTH_ACTIONS)
        if not total:
            return
        r.metrics.append(Metric(
            key="auth.ssh_events", value=total, section="router",
            label="SSH authentication events",
        ))
        self._ssh_new_account(q, r, baseline)
        self._ssh_external_logon(q, r, profile)
        self._ssh_failure_burst(q, r)

    def _ssh_new_account(self, q: EventQuery, r: AnalyzerResult, baseline: Baseline) -> None:
        if not baseline.has_baseline():
            return
        accounts = {a for a in q.distinct_values("user", kind=EventKind.AUTH,
                                                  action="ssh_accepted") if a}
        novel = baseline.novel(EntityType.USER, sorted(accounts))
        if not novel:
            return
        r.signals.append(Signal(
            id="auth.ssh_new_account",
            analyzer=self.name,
            title=f"{len(novel)} account(s) authenticated over SSH for the first time",
            taxonomy="auth.ssh_new_account",
            severity_hint=Severity.MEDIUM,
            confidence=0.55,
            entities=[Entity(type=EntityType.USER, value=a, role="account")
                     for a in sorted(novel)[:10]],
            evidence={"accounts": sorted(novel)[:20]},
            narrative_hint=(
                "A never-seen-before account logging in over SSH is routine "
                "the first time this analyzer runs, and routine again for a "
                "legitimate new user - but on a host with a small, known set "
                "of SSH users it is exactly what a newly created or "
                "compromised-then-repurposed account would look like too. "
                "Check whether this account is expected."
            ),
        ))

    def _ssh_external_logon(self, q: EventQuery, r: AnalyzerResult, profile: Profile) -> None:
        rows = q.sample(n=_SSH_SAMPLE_LIMIT, kind=EventKind.AUTH, action="ssh_accepted")
        external: dict[str, dict] = {}
        for row in rows:
            src_ip = row.get("src_ip")
            if not src_ip or profile.is_internal(src_ip):
                continue
            external.setdefault(src_ip, row)
        for src_ip, row in sorted(external.items()):
            r.signals.append(Signal(
                id=f"auth.ssh_external_logon.{src_ip}",
                analyzer=self.name,
                title=f"SSH logon accepted from external address {src_ip}",
                taxonomy="auth.ssh_external_logon",
                severity_hint=Severity.HIGH,
                confidence=0.7,
                entities=[
                    Entity(type=EntityType.IP, value=src_ip, role="source"),
                    Entity(type=EntityType.USER, value=row.get("user") or "unknown",
                          role="account"),
                ],
                evidence={
                    "src_ip": src_ip, "account": row.get("user"),
                    "method": row.get("proto"), "device": row.get("device"),
                },
                narrative_hint=(
                    "A successful SSH logon from outside this network is "
                    "either an intentionally exposed/port-forwarded service, "
                    "an authorised remote-access path, or unauthorised access "
                    "reaching this host directly - confirm which. Unlike "
                    "perimeter scanning, an *accepted* external SSH session "
                    "has no innocent default explanation."
                ),
            ))

    def _ssh_failure_burst(self, q: EventQuery, r: AnalyzerResult) -> None:
        """The single most standard brute-force signature there is - not yet
        observed on this device (no attempt has occurred), but the format is
        universal enough across OpenSSH versions to build confidently ahead
        of the first real one."""
        total = q.count(kind=EventKind.AUTH, action=_SSH_FAILURE_ACTIONS)
        if total < _SSH_FAILURE_BURST_MIN:
            return
        by_source = q.top("src_ip", n=10, kind=EventKind.AUTH, action=_SSH_FAILURE_ACTIONS)
        by_account = q.top("user", n=10, kind=EventKind.AUTH, action=_SSH_FAILURE_ACTIONS)
        r.signals.append(Signal(
            id="auth.ssh_failure_burst",
            analyzer=self.name,
            title=f"{total} failed/invalid SSH logon attempt(s) this run",
            taxonomy="auth.ssh_failure_burst",
            severity_hint=Severity.MEDIUM,
            confidence=0.6,
            entities=[Entity(type=EntityType.IP, value=ip, role="source")
                     for ip, _n in by_source[:10] if ip],
            evidence={
                "failed_attempts": total, "by_source": by_source, "by_account": by_account,
            },
            narrative_hint=(
                "A cluster of failed or invalid-user SSH attempts is the "
                "classic shape of brute-force scanning. Many distinct "
                "attempted usernames from one source is automated scanning; "
                "many attempts against one real account is a targeted "
                "attempt. Check whether any later logon from the same "
                "source succeeded, and whether this host's SSH port is "
                "reachable from anywhere it should not be."
            ),
        ))
