"""LibreNMS syslog source: firewall/kernel lines plus router system events.

Two hard-won behaviours of this API are encoded here as code rather than as
prompt warnings, because both produce silent, confident data loss:

  * ``from``/``to`` MUST be ``YYYY-MM-DD HH:MM:SS`` strings. Epoch integers
    return HTTP 200 with ``total: 0`` - indistinguishable from a dead feed.
  * HTTP 200 proves the request parsed, nothing more. The only success signal
    is a non-zero record count over an inspected timestamp span.

When a device returns zero rows, :meth:`self_test` runs the differential probes
that separate "my query was malformed" from "the feed stopped". That decision is
never left to a model.

Device selection: ``DAWNPATROL_SOURCE_LIBRENMS_DEVICES`` pins an explicit list
when set. Unset, every device LibreNMS reports is collected - discovered fresh
each run from ``/devices``, so a device added on the LibreNMS side is picked up
without a config change here. That same call is also where hostname/hardware/OS/
status context comes from, attached to the health record.

Every device with an IP is also registered in ``ctx.devices`` (see
``dawnpatrol/devices.py``) - the cross-source, IP-keyed device table the
internal investigation agent sees a summary of every run and can query in
full through its own ``get_device_directory`` tool. This plugin has no
dedicated MCP tool of its own: metadata this source contributes reaches an
external agent only through that same generic, cross-source
``get_device_directory`` MCP tool (``mcpserver/tools.py``), never through
anything LibreNMS-specific - the MCP surface exposes core functionality, not
per-plugin ones.

``DNSMASQ-DHCP`` lease lines are a second, independent contribution to that
same directory: a ``DHCPACK`` carries a real hostname and MAC address for
devices that have neither SNMP presence nor a local DNS resolver - which is
most of what the IoT/DMZ segment gateways can offer at all. Confirmed against
the real feed on all three devices (main router and both OpenWRT gateways)
before being encoded here, not assumed from documentation.

``DNSMASQ`` (no ``-DHCP`` suffix) query-log lines are a third: a segment
gateway that runs its own local dnsmasq as the resolver for its clients (the
IoT gateway, 10.128.10.8) can be configured to log every query it answers,
which is real per-device DNS visibility for a segment `pihole_dns.py` never
sees directly. Two things confirmed against the real live feed (device 7,
12/48h pulls via the LibreNMS API) before this was encoded, both classic
"looks like a query, isn't" traps:

  * Every dnsmasq restart logs a bulk self-test sweep - one ``query[PTR]``
    plus a ``config``/``DHCP``/bare-hosts-path answer line, per statically
    known host and DHCP lease, all at one identical timestamp, all from
    client ``127.0.0.1``. A single observed restart produced 118+80+36+2
    such lines. None of it is a real device asking to resolve anything;
    excluding ``client == 127.0.0.1`` unconditionally removes the whole
    artifact, regardless of verb - every real client query observed live
    came from a real ``10.128.50.x`` address, never loopback.
  * ``forwarded``/``reply``/``cached`` lines answer a query already logged
    by its ``query[...]`` line - often several ``reply`` lines for one
    query (one per round-robin A record: a single lookup for
    ``jnn-pa.googleapis.com`` produced 8). Turning those into events too
    would multiply one real lookup into many DNS events, so only the
    ``query[...]`` line becomes an ``Event`` here - one event per lookup,
    the same shape `pihole_dns.py` already produces.

The double-visibility this creates - the same resolution can now show up
once here (real IoT client IP) and once more in Pi-hole's own query log
(client_ip=10.128.10.8, since the gateway is itself a DNS client of
Pi-hole for its upstream lookups) - is a network fact, not a parsing bug,
and is documented in `profile.yml`'s `known_quirks` rather than
deduplicated here: the two sources are recording two different hops of the
same lookup, not the same event twice.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from ..context import RunContext
from ..devices import DeviceDirectory
from ..models import UTC, CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_env, read_int, read_list, read_secret
from .base import Source

log = logging.getLogger(__name__)

#: iptables-style kernel line. Field order varies by firmware, so each field is
#: matched independently rather than as one positional pattern. Some firmware
#: (OpenWrt-based DMZ/IoT gateways observed in production) prefixes the action
#: with a kernel uptime stamp - "[4081245.823274] drop wan out: IN=..." - so the
#: optional bracketed group is required, not cosmetic: without it, every one of
#: that firmware's DROP/ACCEPT/REJECT lines silently falls through to a plain
#: SYSTEM event instead of FIREWALL, indistinguishable from DHCP chatter and
#: invisible to every firewall-shaped analyzer.
_ACTION_RE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?(?P<action>DROP|ACCEPT|REJECT)\b", re.IGNORECASE)
_FIELD_RE = re.compile(r"\b(IN|OUT|SRC|DST|LEN|TTL|PROTO|SPT|DPT|MAC)=([^\s]*)")

#: PROTO sometimes arrives as a raw number; unify so breakdowns do not fragment.
_PROTO_NUMBERS = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp",
                  "47": "gre", "50": "esp", "58": "icmpv6", "89": "ospf"}

#: 802.11 deauthentication lines carry a client MAC - the closest thing to a
#: device-authentication event this data actually has (see auth_activity.py).
#: Matches both WLCEVENTD's "Deauth_ind AA:BB:..." and HOSTAPD's
#: "STA aa:bb:... IEEE 802.11: deauthenticated ...".
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")

#: OpenWRT LuCI web-UI login, format confirmed live on both segment gateways
#: (devices 4 and 7, 72h pull): "[info] luci: accepted login on / for root
#: from 10.128.10.35". Only "accepted" was observed live; "failed" is LuCI's
#: own stable, symmetric wording (dispatcher.lua logs both outcomes through
#: the same call shape) - built ahead of the first real one, the same
#: reasoning _parse_sshd_session already applies to OpenSSH's
#: "Failed"/"Invalid user" lines never having occurred on this deployment.
_LUCI_LOGIN_RE = re.compile(
    r"^\[info\]\s+luci:\s+(?P<result>accepted|failed)\s+login\s+on\s+\S+\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

#: ASUS/Asuswrt-family web-UI login, format confirmed live on the edge router
#: (device 3): "[LOGIN][http][Web] successful (10.128.10.35)" and
#: "... failed (...)". The IoT gateway's own HTTPD-tagged web service
#: produces the identical line shape but spells the success case "successed"
#: (a firmware translation quirk, not a different outcome) - `success\w*`/
#: `fail\w*` matches every variant without caring about the exact suffix.
#: No username in this line - only the ASUS-style bare admin login has one.
_ASUS_WEBLOGIN_RE = re.compile(
    r"^\[LOGIN\]\[http\]\[Web\]\s+(?P<result>success\w*|fail\w*)\s+\((?P<ip>[\d.]+)\)",
    re.IGNORECASE,
)

#: DNSMASQ-DHCP lines, format confirmed against the real feed on all three
#: devices (main router + both OpenWRT segment gateways):
#:   DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff
#:   DHCPOFFER(eth0) 10.0.0.5 aa:bb:cc:dd:ee:ff
#:   DHCPREQUEST(eth0) 10.0.0.5 aa:bb:cc:dd:ee:ff
#:   DHCPACK(eth0) 10.0.0.5 aa:bb:cc:dd:ee:ff optional-hostname
#:   DHCPRELEASE(eth0) 10.0.0.5 aa:bb:cc:dd:ee:ff
#: Only DHCPACK ever carries a hostname, and only when the client sent one.
_DHCP_VERB_RE = re.compile(
    r"^(DHCPACK|DHCPREQUEST|DHCPOFFER|DHCPDISCOVER|DHCPRELEASE|DHCPINFORM)"
    r"\([^)]*\)\s*(.*)$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: dnsmasq query-log line (program tag "DNSMASQ", not "DNSMASQ-DHCP"), format
#: confirmed against the real feed (device 7, the IoT segment gateway):
#:   119 10.128.50.163/51007 query[A] jnn-pa.googleapis.com from 10.128.50.163
#:   120 10.128.50.163/53438 query[AAAA] jnn-pa.googleapis.com from 10.128.50.163
#: Only the `query[...]` verb ever reaches this pattern - `forwarded`,
#: `reply`, `cached`, `config`, `DHCP`, and the bare hosts-file-path verb are
#: deliberately never matched here (see the module docstring for why: they
#: either multiply one lookup into several answer lines, or are dnsmasq's own
#: post-restart self-test against 127.0.0.1, never a real client query).
_DNSMASQ_QUERY_RE = re.compile(
    r"^\d+\s+(?P<client>\S+?)/\d+\s+query\[(?P<qtype>[A-Za-z0-9]+)\]\s+"
    r"(?P<domain>\S+)\s+from\s+\S+\s*$"
)


def _parse_dhcp(message: str) -> dict[str, Any] | None:
    """Parse one DNSMASQ-DHCP line into verb/ip/mac/hostname, or None if the
    line is not a lease-lifecycle line at all (pool-exhaustion errors, domain
    suffix chatter, etc. - dnsmasq logs plenty of those under the same
    program tag)."""
    m = _DHCP_VERB_RE.match(message.strip())
    if not m:
        return None
    verb, rest = m.group(1), m.group(2)
    tokens = rest.split()
    ip = mac = hostname = None
    idx = 0
    if tokens and _IPV4_RE.match(tokens[0]):
        ip = tokens[0]
        idx = 1
    if len(tokens) > idx and _MAC_RE.fullmatch(tokens[idx]):
        mac = tokens[idx].lower()
        idx += 1
    if len(tokens) > idx:
        hostname = tokens[idx]
    return {"verb": verb, "ip": ip, "mac": mac, "hostname": hostname}


def _parse_dnsmasq_query(message: str) -> dict[str, Any] | None:
    """Parse one dnsmasq ``query[...]`` line into client/qtype/domain, or
    None for every other verb (forwarded/reply/cached/config/DHCP/etc.) or a
    query from ``127.0.0.1`` - the post-restart self-test sweep, never a
    real device (see the module docstring)."""
    m = _DNSMASQ_QUERY_RE.match(message.strip())
    if not m:
        return None
    client = m.group("client")
    if client == "127.0.0.1":
        return None
    return {"client": client, "qtype": m.group("qtype"), "domain": m.group("domain")}


def _parse_router_admin_login(program: str, message: str) -> dict[str, Any] | None:
    """Web-UI admin login on a router or segment gateway, from either of two
    confirmed-live formats - LuCI (program ``UHTTPD``) or the ASUS-family web
    GUI (program ``HTTPD``). Returns None for any other line under either
    tag; both services log plenty of non-login chatter under the same
    program name."""
    if program == "UHTTPD":
        m = _LUCI_LOGIN_RE.match(message.strip())
        if not m:
            return None
        return {"success": m.group("result").lower() == "accepted",
                "ip": m.group("ip"), "user": m.group("user")}
    if program == "HTTPD":
        m = _ASUS_WEBLOGIN_RE.match(message.strip())
        if not m:
            return None
        return {"success": m.group("result").lower().startswith("success"),
                "ip": m.group("ip"), "user": None}
    return None


#: Windows Security auditing lines, forwarded as the full rendered event text
#: (not structured XML) by whatever agent is shipping this device's syslog.
#: Confirmed against the real feed (device 8, a Windows 11 box): fields are
#: "Label:" followed by one or two literal `\011` escapes (not real tab
#: bytes - this forwarder writes the octal escape as text) then the value,
#: blocks separated by two-or-more spaces. Classification is by the event's
#: fixed leading sentence - Microsoft's canned templates for these EventIDs
#: (4624/4625/4672/4648/4740) are stable across Windows versions, so matching
#: the sentence is as reliable as matching a numeric EventID would be, and
#: this forwarder does not expose the numeric ID at all.
_WIN_FIELD_SEP = r"(?:\\011)+\s*"

#: Numeric Windows logon type -> short label. Kept to fit the `proto` column
#: (see _parse_windows_security_audit for why that column, of all of them).
_WIN_LOGON_TYPES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service",
    "7": "unlock", "8": "net_clear", "9": "new_cred", "10": "rdp",
    "11": "cached",
}

#: Windows Defender's REAL detection template, matched positively - after
#: TWO rounds of a new benign Defender message type breaking an earlier
#: inverse-match design (health heartbeats, then scan lifecycle and history
#: cleanup, then routine configuration-hash changes and security
#: intelligence version updates - all real, all live, all false HIGH-severity
#: positives), enumerating "everything benign" proved to be an open-ended
#: list this device kept extending. Microsoft's actual detection template
#: (EventID 1116) is stable and well-documented across Windows versions:
#: "...has detected malware or other potentially unwanted software," always
#: paired with a named Threat/Category/Path the routine templates never
#: carry. Add to this tuple only when a genuinely new *detection* wording is
#: confirmed live - never touch it to suppress a false positive; enumerating
#: benign wording is what got this design into trouble twice already.
_DEFENDER_DETECTION_PREFIXES = (
    "Microsoft Defender Antivirus has detected malware or other potentially unwanted software",
)


def _win_field(section: str, label: str) -> str | None:
    """One labelled value out of a Windows Security audit message, or None
    if absent or rendered as "-" (Microsoft's own placeholder for "not
    applicable to this logon", e.g. Source Network Address on a local
    service logon)."""
    m = re.search(rf"{re.escape(label)}:{_WIN_FIELD_SEP}([^\s].*?)(?=\s{{2,}}\S|\Z)", section)
    if not m:
        return None
    value = m.group(1).strip()
    return value if value and value != "-" else None


def _win_account(message: str) -> str | None:
    """The account the logon is *about*, not the Subject requesting it (for
    a service logon Subject is almost always SYSTEM/services.exe, which is
    not useful to track) - so search from the "New Logon" or "Account For
    Which Logon Failed" marker first, and only fall back to the first
    "Account Name" in the whole message if neither is present."""
    for marker in ("Account For Which Logon Failed:", "New Logon:"):
        idx = message.find(marker)
        if idx != -1:
            name = _win_field(message[idx:], "Account Name")
            if name:
                return name
    return _win_field(message, "Account Name")


def _parse_windows_defender(message: str, common: dict[str, Any]) -> Event | None:
    if not message.startswith(_DEFENDER_DETECTION_PREFIXES):
        return None
    return Event(kind=EventKind.IDS, action="detection", **common)


#: Classic OpenSSH auth-outcome lines, unchanged across decades of versions -
#: confirmed against the real feed (device 6, this session's own Fedora
#: host): "Accepted password for alice from 10.128.10.35 port 62404 ssh2"
#: and the pam_unix session lines. "Failed"/"Invalid user" were not observed
#: live in this deployment (no brute-force attempt has happened), built from
#: the same universally-stable format instead. IPv4 only, deliberately -
#: an IPv6 source simply will not populate src_ip, rather than risk a loose
#: pattern matching something it should not.
_SSH_IPV4 = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_SSH_ACCEPTED_RE = re.compile(
    rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {_SSH_IPV4} port (?P<port>\d+)")
_SSH_FAILED_RE = re.compile(
    rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from {_SSH_IPV4} "
    rf"port (?P<port>\d+)")
_SSH_INVALID_USER_RE = re.compile(rf"^Invalid user (?P<user>\S+) from {_SSH_IPV4}")
_SSH_SESSION_OPEN_RE = re.compile(r"session opened for user (?P<user>[^\s(]+)")
_SSH_SESSION_CLOSE_RE = re.compile(r"session closed for user (?P<user>[^\s(]+)")

#: Auth method -> short label, to fit the `proto` column (same reuse as
#: Windows logon type - see _parse_windows_security_audit).
_SSH_METHODS = {"password": "password", "publickey": "publickey", "none": "none",
                "keyboard-interactive": "kbdint", "keyboard-interactive/pam": "kbdint"}


_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class LibreNMSSyslogSource(Source):
    name = "librenms_syslog"
    kinds = frozenset({EventKind.FIREWALL, EventKind.SYSTEM, EventKind.AUTH, EventKind.DNS})
    requires_env = frozenset({"DAWNPATROL_SOURCE_LIBRENMS_URL", "DAWNPATROL_SOURCE_LIBRENMS_TOKEN"})
    max_window_hours = None

    PAGE_SIZE = 5000

    # ----- configuration ---------------------------------------------------- #

    @property
    def base_url(self) -> str:
        return (read_env("DAWNPATROL_SOURCE_LIBRENMS_URL", "") or "").rstrip("/")

    @property
    def token(self) -> str:
        return read_secret("DAWNPATROL_SOURCE_LIBRENMS_TOKEN").get()

    @property
    def devices(self) -> list[str]:
        return read_list("DAWNPATROL_SOURCE_LIBRENMS_DEVICES") or []

    @property
    def timeout(self) -> int:
        return read_int("DAWNPATROL_SOURCE_LIBRENMS_TIMEOUT", 60)

    @property
    def verify_tls(self) -> bool:
        raw = read_env("DAWNPATROL_SOURCE_LIBRENMS_VERIFY_TLS", "true")
        return (raw or "true").lower() not in {"0", "false", "no"}

    def _headers(self) -> dict[str, str]:
        return {"X-Auth-Token": self.token, "Accept": "application/json"}

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, verify=self.verify_tls,
                            headers=self._headers())

    # ----- device directory --------------------------------------------------- #

    def _device_directory(self, client: httpx.Client) -> dict[str, dict[str, Any]]:
        """Every device LibreNMS reports, keyed by device_id (as a string).

        One unpaginated call - LibreNMS returns its full device list in a
        single response, unlike the syslog endpoint. Used both to auto-discover
        which devices to collect from and to attach hostname/hardware/OS/status
        context wherever a device id would otherwise be a bare number.
        """
        resp = client.get(f"{self.base_url}/devices")
        resp.raise_for_status()
        payload = resp.json()
        directory: dict[str, dict[str, Any]] = {}
        for d in payload.get("devices") or []:
            device_id = d.get("device_id")
            if device_id is None:
                continue
            directory[str(device_id)] = {
                "hostname": d.get("hostname") or d.get("sysName") or "",
                "ip": d.get("ip") or "",
                "hardware": d.get("hardware") or "",
                "os": d.get("os") or "",
                "version": d.get("version") or "",
                "status": "up" if str(d.get("status")) == "1" else "down",
                "uptime_seconds": _as_int(d.get("uptime")),
                "location": d.get("location") or "",
            }
        return directory

    def _resolve_devices(self, client: httpx.Client) -> tuple[list[str], dict[str, dict[str, Any]]]:
        """Explicit config wins; otherwise every device LibreNMS reports.

        Directory-fetch failure is never fatal here - it only costs the
        hostname/hardware enrichment, and (when no explicit list is set) is
        surfaced through the empty device list that follows, not swallowed.
        """
        directory: dict[str, dict[str, Any]] = {}
        try:
            directory = self._device_directory(client)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not fetch LibreNMS device directory: %s", exc)
        devices = self.devices or sorted(directory, key=int)
        return devices, directory

    def _populate_device_directory(self, devices: DeviceDirectory,
                                   directory: dict[str, dict[str, Any]]) -> None:
        """Feed the cross-source device table (see ``devices.py``).

        Keyed by IP, not device_id - a device LibreNMS reports with no IP
        address has nothing to key an entry on and is simply skipped here.
        """
        for meta in directory.values():
            ip = meta.get("ip")
            if not ip:
                continue
            devices.update(
                ip, source=self.name, role="librenms-managed",
                hostname=meta.get("hostname"), hardware=meta.get("hardware"),
                os=meta.get("os"), version=meta.get("version"),
                status=meta.get("status"), uptime_seconds=meta.get("uptime_seconds"),
                location=meta.get("location"),
            )

    def _populate_dhcp_devices(self, devices: DeviceDirectory, events: list[Event]) -> None:
        """Feed the cross-source device table from DHCP lease grants.

        DHCPACK is the only verb that ever carries a hostname, and it is the
        authoritative "this MAC now has this IP" moment - DISCOVER/OFFER/
        REQUEST are the negotiation leading up to it, not a second lease.
        Real hostnames and a stable MAC identity for IoT/DMZ devices that
        have neither SNMP presence nor a local DNS resolver to be identified
        by any other way.
        """
        for ev in events:
            if ev.program != "DNSMASQ-DHCP" or ev.action != "dhcpack" or not ev.src_ip:
                continue
            parsed = _parse_dhcp(ev.message or "")
            if not parsed:
                continue
            devices.update(ev.src_ip, source=self.name, role="dhcp-client",
                          hostname=parsed["hostname"], mac=ev.user)

    # ----- collection -------------------------------------------------------- #

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        effective = self.effective_window(window)
        result = CollectionResult(source=self.name, window=effective, requested_window=window)

        if not self.base_url or not self.token:
            result.errors.append("LibreNMS URL or token not configured")
            return result

        seen: dict[str, Event] = {}
        totals: dict[str, int] = {}
        directory: dict[str, dict[str, Any]] = {}
        with self._client() as client:
            devices, directory = self._resolve_devices(client)
            if not devices:
                result.errors.append(
                    "no devices configured (DAWNPATROL_SOURCE_LIBRENMS_DEVICES) and none "
                    "discovered from LibreNMS's own /devices endpoint"
                )
                return result

            if ctx is not None:
                self._populate_device_directory(ctx.devices, directory)

            for device in devices:
                try:
                    events, reported, pages = self._collect_device(client, device, effective)
                except httpx.HTTPStatusError as exc:
                    code = exc.response.status_code
                    hint = (" - the request was missing or misspelled the X-Auth-Token "
                            "header; this is never evidence the host is down") if code == 401 else ""
                    result.errors.append(f"device {device}: HTTP {code}{hint}")
                    continue
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"device {device}: {type(exc).__name__}: {exc}")
                    continue
                totals[device] = reported
                result.pages += pages
                for ev in events:
                    seen[ev.dedup_key] = ev

        result.events = list(seen.values())
        result.reported_total = sum(totals.values()) if totals else None

        if ctx is not None:
            self._populate_dhcp_devices(ctx.devices, result.events)

        # One summary note, not one per device: a per-device note list is
        # exactly what gets silently capped to the first 5-6 entries by every
        # renderer's SourceHealth.notes truncation. A single line scales to
        # any device count and still carries every device's own record count -
        # full detail on any one device is a get_device_directory call away.
        per_device: list[str] = []
        zero_record: list[str] = []
        for device, reported in sorted(totals.items(), key=lambda kv: int(kv[0])):
            got = sum(1 for e in result.events if e.device == str(device))
            meta = directory.get(device) or {}
            label = meta.get("hostname") or meta.get("ip") or device
            per_device.append(f"{label}={got}" if got == reported else f"{label}={got}/{reported}")
            if got == 0:
                zero_record.append(label)
        if per_device:
            result.notes.append(
                f"{len(totals)} device(s) collected from, records per device: "
                + ", ".join(per_device)
            )
        if zero_record:
            result.notes.append(
                f"{len(zero_record)} device(s) returned zero records this run: "
                + ", ".join(zero_record) + " - consistent with the host being off "
                "or not configured to forward syslog, not necessarily a collection "
                "failure."
            )
        return result

    def _collect_device(self, client: httpx.Client, device: str,
                        window: Window) -> tuple[list[Event], int, int]:
        events: list[Event] = []
        offset, pages, reported = 0, 0, 0
        while True:
            params = {
                "from": window.start_str,   # string form is mandatory - see module docstring
                "to": window.end_str,
                "limit": self.PAGE_SIZE,
                "start": offset,
            }
            url = f"{self.base_url}/logs/syslog/{device}?{urlencode(params)}"
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.json()
            pages += 1
            reported = int(payload.get("total") or 0)
            logs = payload.get("logs") or []
            for entry in logs:
                ev = self._normalize(entry, device)
                if ev is not None:
                    events.append(ev)
            offset += len(logs)
            # `total` drifts upward during a paginated read because syslog is
            # ingested live; guard on a short page as well as the offset.
            if len(logs) < self.PAGE_SIZE or offset >= reported or pages > 400:
                break
        return events, reported, pages

    # ----- normalization ------------------------------------------------------ #

    def _normalize(self, entry: dict[str, Any], device: str) -> Event | None:
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is None:
            return None
        program = (entry.get("program") or "").upper()
        message = entry.get("msg") or entry.get("message") or ""
        seq = entry.get("seq") or entry.get("id")
        dedup = Event.make_dedup_key(self.name, device, seq, entry.get("timestamp"), message[:80])

        common: dict[str, Any] = {
            "ts": ts,
            "source": self.name,
            "dedup_key": dedup,
            "device": str(device),
            "program": program or None,
            "severity": _severity_name(entry.get("level")),
            "message": message[:2000] or None,
        }

        match = _ACTION_RE.match(message)
        if program == "KERNEL" and match:
            fields = dict(_FIELD_RE.findall(message))
            proto = (fields.get("PROTO") or "").lower()
            proto = _PROTO_NUMBERS.get(proto, proto) or None
            return Event(
                kind=EventKind.FIREWALL,
                action=match.group("action").lower(),
                proto=proto,
                iface_in=fields.get("IN") or None,
                iface_out=fields.get("OUT") or None,
                src_port=_as_int(fields.get("SPT")),
                dst_port=_as_int(fields.get("DPT")),
                ttl=_as_int(fields.get("TTL")),
                pkt_len=_as_int(fields.get("LEN")),
                **self.assign_zones(src_ip=fields.get("SRC") or None,
                                    dst_ip=fields.get("DST") or None),
                **common,
            )

        # VPN daemon output is the only remote-access evidence in this dataset -
        # and in production it has turned out to be lifecycle noise (startup,
        # TUN/TAP up/down, SIGTERM), never a per-session "peer X authenticated"
        # line. Still classified AUTH so a real deployment that does forward
        # per-session lines is picked up automatically; see auth_activity.py's
        # docstring for what this means for VPN-specific analysis today.
        # SSHD is deliberately not in this set - it gets its own real parser
        # below (_parse_sshd_session), not blanket lifecycle-noise treatment.
        if program.startswith("VPNSERVER") or program in {"OPENVPN", "PPTPD"}:
            return Event(kind=EventKind.AUTH, **common)

        # Wi-Fi deauthentication: real device-authentication evidence this
        # network actually produces. `user` is repurposed to carry the client
        # MAC address - the only stable identity 802.11 gives us here.
        if program in {"WLCEVENTD", "HOSTAPD"} and "deauth" in message.lower():
            mac = _MAC_RE.search(message)
            if mac:
                return Event(kind=EventKind.AUTH, action="deauth",
                            user=mac.group(1).lower(), **common)

        # DHCP lease lines: real device identity (MAC, sometimes a hostname)
        # for segments with no SNMP presence and no local DNS resolver - see
        # _populate_dhcp_devices(), which reads these back out of collect()'s
        # own result.events to feed the device directory.
        if program == "DNSMASQ-DHCP":
            parsed = _parse_dhcp(message)
            if parsed and parsed["mac"]:
                return Event(
                    kind=EventKind.SYSTEM,
                    action=parsed["verb"].lower(),
                    user=parsed["mac"],
                    **self.assign_zones(src_ip=parsed["ip"]),
                    **common,
                )

        # dnsmasq query log: real per-client DNS visibility for a segment
        # gateway that resolves for its own clients (the IoT gateway) rather
        # than forwarding straight to Pi-hole. One Event per query line only -
        # see the module docstring and _parse_dnsmasq_query for why every
        # other verb, and every 127.0.0.1 "query", is deliberately excluded.
        if program == "DNSMASQ":
            parsed = _parse_dnsmasq_query(message)
            if parsed:
                return Event(
                    kind=EventKind.DNS,
                    domain=parsed["domain"],
                    qtype=parsed["qtype"],
                    blocked=False,  # this dnsmasq instance has no blocklist
                    **self.assign_zones(client_ip=parsed["client"]),
                    **common,
                )

        # Router/gateway web-UI admin login - LuCI on the OpenWRT segment
        # gateways (program "UHTTPD"), the native web GUI on the ASUS edge
        # router and, with a firmware translation quirk, on the IoT gateway's
        # own HTTPD-tagged service too (program "HTTPD"). See
        # _parse_router_admin_login and the module docstring for both
        # confirmed-live formats.
        if program in {"UHTTPD", "HTTPD"}:
            parsed = _parse_router_admin_login(program, message)
            if parsed:
                return Event(
                    kind=EventKind.AUTH,
                    action="web_login_success" if parsed["success"] else "web_login_failed",
                    user=parsed["user"],
                    **self.assign_zones(src_ip=parsed["ip"]),
                    **common,
                )

        # Windows Security auditing: real per-account authentication evidence
        # for any device with Windows logs forwarded here (see device
        # directory / profile for which). `.startswith` rather than `==`
        # because the syslog `program` field is truncated to ~32 chars and
        # this program name is right at that boundary on some builds.
        if program.startswith("MICROSOFT-WINDOWS-SECURITY-AUDIT"):
            ev = self._parse_windows_security_audit(message, common)
            if ev is not None:
                return ev

        if program.startswith("MICROSOFT-WINDOWS-WINDOWS_DEFEND"):
            ev = _parse_windows_defender(message, common)
            if ev is not None:
                return ev

        # Classic OpenSSH auth lines - "SSHD-SESSION" on newer systemd-managed
        # builds (confirmed live, device 6), plain "SSHD" on older ones.
        if program.startswith("SSHD"):
            ev = self._parse_sshd_session(message, common)
            if ev is not None:
                return ev

        return Event(kind=EventKind.SYSTEM, **common)

    def _parse_windows_security_audit(self, message: str,
                                      common: dict[str, Any]) -> Event | None:
        """Classify by the event's fixed leading sentence - see _WIN_FIELD_SEP's
        docstring for why that is reliable here. The lockout/explicit-credential
        branches are unverified against this deployment's real data (neither has
        occurred), built from Microsoft's documented, stable event templates
        instead - if the field markers below ever don't match a real one of
        these, the generic Account Name fallback still gets *something* rather
        than nothing."""
        if message.startswith("An account was successfully logged on"):
            action, account = "logon_success", _win_account(message)
        elif message.startswith("An account failed to log on"):
            action, account = "logon_failed", _win_account(message)
        elif message.startswith("Special privileges assigned to new logon"):
            action, account = "privileged", _win_field(message, "Account Name")
        elif message.startswith("A logon was attempted using explicit credentials"):
            action = "explicit_creds"
            idx = message.find("Account Whose Credentials Were Used:")
            account = _win_field(message[idx:], "Account Name") if idx != -1 else None
        elif message.startswith("A user account was locked out"):
            action = "lockout"
            idx = message.find("Account That Was Locked Out:")
            account = _win_field(message[idx:], "Account Name") if idx != -1 else None
        else:
            return None

        logon_type = _win_field(message, "Logon Type")
        src_ip = _win_field(message, "Source Network Address")
        kwargs: dict[str, Any] = {
            **common,
            "kind": EventKind.AUTH,
            "action": action,
            "user": account,
            # `proto` has no meaning for an AUTH event; repurposed to carry the
            # logon type (interactive/network/service/rdp/...) the same way
            # `user` carries a MAC for Wi-Fi deauth above - both are "the one
            # extra classifier this event type needs" borrowing a column that
            # is otherwise always empty for this kind.
            "proto": _WIN_LOGON_TYPES.get(logon_type) if logon_type else None,
        }
        if src_ip:
            kwargs.update(self.assign_zones(src_ip=src_ip))
        return Event(**kwargs)

    def _parse_sshd_session(self, message: str, common: dict[str, Any]) -> Event | None:
        """session_open/close are parsed for structure but excluded from the
        auth-outcome metric in auth_activity.py - every accepted login also
        produces a session_open line, and counting both would double the
        headline number for the same event."""
        if m := _SSH_ACCEPTED_RE.match(message):
            action = "ssh_accepted"
        elif m := _SSH_FAILED_RE.match(message):
            action = "ssh_failed"
        else:
            m = None

        if m:
            kwargs: dict[str, Any] = {
                **common, "kind": EventKind.AUTH, "action": action,
                "user": m.group("user"),
                "src_port": _as_int(m.group("port")),
                "proto": _SSH_METHODS.get(m.group("method"), m.group("method")[:16]),
            }
            kwargs.update(self.assign_zones(src_ip=m.group("ip")))
            return Event(**kwargs)

        if m := _SSH_INVALID_USER_RE.match(message):
            kwargs = {**common, "kind": EventKind.AUTH, "action": "ssh_invalid",
                     "user": m.group("user")}
            kwargs.update(self.assign_zones(src_ip=m.group("ip")))
            return Event(**kwargs)

        if m := _SSH_SESSION_OPEN_RE.search(message):
            return Event(kind=EventKind.AUTH, action="session_open",
                        user=m.group("user"), **common)

        if m := _SSH_SESSION_CLOSE_RE.search(message):
            return Event(kind=EventKind.AUTH, action="session_close",
                        user=m.group("user"), **common)

        return None

    # ----- differential probes -------------------------------------------------- #

    def self_test(self, ctx: RunContext) -> list[Probe]:
        """Four probes that separate a malformed query from a dead feed.

        Only "no-filter also empty" plus "control device also empty" justifies
        reporting an outage. Every probe result is recorded, not just the one
        that returned nothing.
        """
        probes: list[Probe] = []
        if not self.base_url or not self.token:
            return [Probe(name="config", request="(none)", ok=False,
                          detail="URL or token missing")]

        window = ctx.window

        with self._client() as client:
            devices, _directory = self._resolve_devices(client)
            primary = devices[0] if devices else None
            controls = devices[1:3]
            if primary:
                probes.append(self._probe(client, "no-time-filter",
                                          f"/logs/syslog/{primary}?limit=1"))
                probes.append(self._probe(
                    client, "narrow-window",
                    f"/logs/syslog/{primary}?"
                    f"{urlencode({'from': window.last_hour().start_str, 'to': window.end_str, 'limit': 1})}",
                ))
            for control in controls:
                probes.append(self._probe(
                    client, f"control-device-{control}",
                    f"/logs/syslog/{control}?"
                    f"{urlencode({'from': window.start_str, 'to': window.end_str, 'limit': 1})}",
                ))
            probes.append(self._probe(client, "auth-check", "/devices?limit=1"))
        return probes

    def _probe(self, client: httpx.Client, name: str, path: str) -> Probe:
        url = f"{self.base_url}{path}"
        try:
            resp = client.get(url)
        except Exception as exc:  # noqa: BLE001
            return Probe(name=name, request=path, ok=False, detail=f"{type(exc).__name__}: {exc}")
        records = None
        detail = ""
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                records = payload.get("total")
                if records is None and isinstance(payload.get("devices"), list):
                    records = len(payload["devices"])
                if payload.get("error"):
                    detail = str(payload["error"])[:200]
        except Exception:  # noqa: BLE001
            detail = resp.text[:200]
        if resp.status_code == 401:
            detail = ("HTTP 401 means the request lacked the auth header. "
                      "This is never evidence that the host is down.")
        return Probe(name=name, request=path, ok=resp.status_code == 200,
                     status=resp.status_code, records=records, detail=detail)

    def extra_health_notes(self, result: CollectionResult) -> list[str]:
        notes = []
        emerg = sum(1 for e in result.events if (e.severity or "") == "emerg")
        if emerg:
            programs: dict[str, int] = {}
            for e in result.events:
                if (e.severity or "") == "emerg":
                    programs[e.program or "?"] = programs.get(e.program or "?", 0) + 1
            top = ", ".join(f"{k}={v}" for k, v in
                            sorted(programs.items(), key=lambda kv: -kv[1])[:5])
            notes.append(
                f"{emerg} entries carry 'emerg' severity, broken down by program: {top}. "
                "Consumer router firmware commonly mislabels routine chatter at this "
                "level; the count alone is not a severity signal."
            )
        return notes


def _parse_timestamp(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), UTC)
    text = str(raw).strip().replace("T", " ")
    if "." in text:
        text = text.split(".", 1)[0]
    text = text.replace("Z", "").strip()
    for fmt in (_DATE_FMT, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


_SEVERITY_NAMES = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning",
                   5: "notice", 6: "info", 7: "debug"}


def _severity_name(level: Any) -> str | None:
    if level is None:
        return None
    if isinstance(level, int) or (isinstance(level, str) and level.isdigit()):
        return _SEVERITY_NAMES.get(int(level), str(level))
    return str(level).lower()
