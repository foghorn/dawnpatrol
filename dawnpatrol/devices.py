"""Cross-source device directory: a per-run registry of network devices.

Built fresh every run - nothing here is persisted between runs, and there is
no config file to maintain. Any :class:`~dawnpatrol.sources.base.Source` can
call ``ctx.devices.update(...)`` from inside its own ``collect()`` to
contribute whatever it happens to know about a device: LibreNMS reports
hostname/hardware/OS/uptime for everything it manages, Pi-hole only ever
sees a bare client IP (and sometimes a name) making DNS queries. Both are
legitimate, partial views of the same key.

Keyed by IP address, not by any one source's internal identifier (LibreNMS's
``device_id`` is only meaningful to LibreNMS) - so contributions from
different sources land on the same entry. Fields accumulate rather than
overwrite: the first non-empty value for a field wins, and every
contributing source and role is recorded rather than only the first, so a
sparse later contribution never clobbers a richer earlier one.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Any

#: Structured fields a source may fill in. First non-empty value wins.
_FIELDS = ("hostname", "hardware", "os", "version", "status", "location", "uptime_seconds")


@dataclass(slots=True)
class DeviceInfo:
    """Everything known about one IP this run, merged across sources."""

    ip: str
    hostname: str = ""
    hardware: str = ""
    os: str = ""
    version: str = ""
    status: str = ""
    location: str = ""
    uptime_seconds: int | None = None
    roles: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    def label(self) -> str:
        return self.hostname or self.ip

    def one_line(self) -> str:
        bits = [self.ip]
        if self.hostname:
            bits.append(self.hostname)
        descriptor = ", ".join(x for x in (self.hardware, self.os) if x)
        if descriptor:
            bits.append(f"({descriptor})")
        if self.status:
            bits.append(f"[{self.status}]")
        if self.roles:
            bits.append("roles=" + "/".join(sorted(self.roles)))
        bits.append("via " + "/".join(sorted(self.sources)))
        return " ".join(bits)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "hardware": self.hardware,
            "os": self.os,
            "version": self.version,
            "status": self.status,
            "location": self.location,
            "uptime_seconds": self.uptime_seconds,
            "roles": sorted(self.roles),
            "sources": sorted(self.sources),
            "notes": list(self.notes),
        }


class DeviceDirectory:
    """Per-run registry of :class:`DeviceInfo`, keyed by IP address.

    Sources run concurrently in the collect stage (``runner.py``'s
    ``ThreadPoolExecutor``), each contributing through its own ``update()``
    calls - a lock guards the shared dict so two sources updating the same
    IP at once cannot interleave a partial write.
    """

    def __init__(self) -> None:
        self._by_ip: dict[str, DeviceInfo] = {}
        self._lock = threading.Lock()

    def update(self, ip: str, *, source: str, role: str = "",
              note: str = "", **fields: Any) -> DeviceInfo | None:
        """Add or merge what ``source`` knows about ``ip``.

        Unknown or empty values in ``fields`` are ignored rather than
        clobbering an existing value - a source with partial knowledge can
        never erase a fuller picture another source already contributed.
        """
        ip = (ip or "").strip()
        if not ip:
            return None
        with self._lock:
            info = self._by_ip.setdefault(ip, DeviceInfo(ip=ip))
            info.sources.add(source)
            if role:
                info.roles.add(role)
            if note and note not in info.notes:
                info.notes.append(note)
            for key in _FIELDS:
                if key not in fields:
                    continue
                value = fields[key]
                if value in (None, ""):
                    continue
                if not getattr(info, key):
                    setattr(info, key, value)
            return info

    def get(self, ip: str) -> DeviceInfo | None:
        return self._by_ip.get((ip or "").strip())

    def all(self) -> list[DeviceInfo]:
        return sorted(self._by_ip.values(), key=_sort_key)

    def __len__(self) -> int:
        return len(self._by_ip)

    def __bool__(self) -> bool:
        return bool(self._by_ip)

    def summary_lines(self, limit: int = 200) -> list[str]:
        return [d.one_line() for d in self.all()[:limit]]

    def to_bundle(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.all()]


def _sort_key(info: DeviceInfo) -> tuple[int, Any]:
    try:
        return (0, ipaddress.ip_address(info.ip))
    except ValueError:
        return (1, info.ip)
