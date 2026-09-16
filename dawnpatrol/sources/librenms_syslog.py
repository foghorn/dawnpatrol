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
#: matched independently rather than as one positional pattern.
_ACTION_RE = re.compile(r"^\s*(?P<action>DROP|ACCEPT|REJECT)\b", re.IGNORECASE)
_FIELD_RE = re.compile(r"\b(IN|OUT|SRC|DST|LEN|TTL|PROTO|SPT|DPT|MAC)=([^\s]*)")

#: PROTO sometimes arrives as a raw number; unify so breakdowns do not fragment.
_PROTO_NUMBERS = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp",
                  "47": "gre", "50": "esp", "58": "icmpv6", "89": "ospf"}

_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class LibreNMSSyslogSource(Source):
    name = "librenms_syslog"
    kinds = frozenset({EventKind.FIREWALL, EventKind.SYSTEM, EventKind.AUTH})
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
        for device, reported in sorted(totals.items(), key=lambda kv: int(kv[0])):
            got = sum(1 for e in result.events if e.device == str(device))
            meta = directory.get(device) or {}
            label = meta.get("hostname") or meta.get("ip") or ""
            descriptor = f" ({label})" if label else ""
            extra = ", ".join(x for x in (meta.get("hardware"), meta.get("os")) if x)
            line = f"device {device}{descriptor}: {got} records (API reported {reported})"
            result.notes.append(f"{line} - {extra}" if extra else line)
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

        # VPN daemon output is the only remote-access evidence in this dataset.
        if program.startswith("VPNSERVER") or program in {"OPENVPN", "SSHD", "PPTPD"}:
            return Event(kind=EventKind.AUTH, **common)

        return Event(kind=EventKind.SYSTEM, **common)

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
