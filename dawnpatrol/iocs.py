"""Indicator-of-compromise lists: loading and matching.

Operators drop published IoC lists (CSV or plain text) into a folder, and every
run checks its firewall and DNS events against them (``analyzers/ioc_match.py``).
``dawnpatrol hunt --ioc-file`` sweeps retained history with the same matcher, so
an indicator published today is also checked against what happened months ago.

Only indicators the event store can observe are kept: IP addresses, CIDR
ranges, domains (which also match their subdomains) and domain suffixes. Other
types in a list - user agents, file hashes, cloud app IDs - are counted and
reported as skipped, never silently dropped.

Two file formats:

* **CSV with a header row.** Recognized columns (case-insensitive): the value
  in ``indicator``/``value``/``ioc``; ``type``; a ``tier`` (T1-T4) or
  ``severity`` (critical/high/medium/low/info); optional ``source``,
  ``campaign``, ``warning``/``notes``, and an expiry in ``alert_until`` or
  ``valid_until`` (YYYY-MM-DD). This reads the MalwareMustDie ARTEX list
  as published, and any list shaped like it.
* **Plain text**, one indicator per line, ``#`` comments. The type is inferred;
  a leading ``*.`` or ``.`` marks a domain suffix. Severity is ``low``, since a
  bare list says nothing about confidence.

Defanged values (``1.2.3[.]4``, ``example[.]com``, ``hxxp://``) are refanged.
Everything read from a list is untrusted text: it is length-capped here and
only ever reaches the model inside the fenced evidence bundle.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from .models import Severity

log = logging.getLogger(__name__)

#: Where the analyzer looks when DAWNPATROL_IOC_PATHS is unset.
DEFAULT_IOC_DIR = "/etc/dawnpatrol/iocs"
#: Larger ranges match too much of the internet to be an indicator.
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 32
_TEXT_CAP = 300

_TIER_SEVERITY = {
    "T1": Severity.CRITICAL,
    "T2": Severity.HIGH,
    "T3": Severity.MEDIUM,
    "T4": Severity.LOW,
}
_TYPE_ALIASES = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-dst": "ip", "ip-src": "ip",
    "ipv4-addr": "ip", "ipv6-addr": "ip",
    "cidr": "cidr", "ipv4-cidr": "cidr", "ipv6-cidr": "cidr", "ip-range": "cidr",
    "domain": "domain", "hostname": "domain", "fqdn": "domain", "domain-name": "domain",
    "domain-suffix": "domain_suffix", "domain_suffix": "domain_suffix",
    "user-agent": "user_agent", "user_agent": "user_agent",
    "user-agent-substring": "user_agent_substring",
    "string-marker": "url_marker", "url-marker": "url_marker", "url_marker": "url_marker",
}
#: Kinds matched against free text (user agents, request URLs), not addresses.
TEXT_KINDS = ("user_agent", "user_agent_substring", "url_marker")
#: Shorter text markers match ordinary URLs and user agents by accident.
MIN_TEXT_MARKER = 6
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
                        r"[a-z0-9-]{2,63}$")


@dataclass(frozen=True, slots=True)
class Indicator:
    value: str               # normalized: address, network, lowercase domain, or text
    kind: str                # ip | cidr | domain | domain_suffix | user_agent |
                             # user_agent_substring | url_marker
    severity: Severity = Severity.LOW
    tier: str = ""
    source: str = ""
    campaign: str = ""
    warning: str = ""
    expires: date | None = None
    origin: str = ""         # file the indicator came from

    def to_evidence(self) -> dict[str, str]:
        out = {"indicator": self.value, "indicator_type": self.kind, "list": self.origin}
        for key in ("tier", "source", "campaign", "warning"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        if self.expires:
            out["alert_until"] = self.expires.isoformat()
        return out


@dataclass
class IocSet:
    indicators: list[Indicator] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    #: type -> count of rows whose type the event store cannot observe.
    skipped_types: dict[str, int] = field(default_factory=dict)
    expired: int = 0
    invalid: int = 0

    def summary(self) -> str:
        parts = [f"{len(self.indicators)} usable indicator(s) from {len(self.files)} file(s)"]
        if self.expired:
            parts.append(f"{self.expired} expired")
        if self.invalid:
            parts.append(f"{self.invalid} unreadable")
        if self.skipped_types:
            kinds = ", ".join(f"{k} {v}" for k, v in sorted(self.skipped_types.items()))
            parts.append(f"not observable here: {kinds}")
        return "; ".join(parts)

    # ----- matching --------------------------------------------------------- #

    def match_ips(self, values: Iterable[str]) -> dict[str, list[Indicator]]:
        """Each address in ``values`` that an ip or cidr indicator covers."""
        exact = {i.value: i for i in self.indicators if i.kind == "ip"}
        nets = [(ipaddress.ip_network(i.value), i) for i in self.indicators if i.kind == "cidr"]
        out: dict[str, list[Indicator]] = {}
        for raw in values:
            if not raw:
                continue
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            hits = [exact[str(addr)]] if str(addr) in exact else []
            hits += [i for net, i in nets if addr.version == net.version and addr in net]
            if hits:
                out[raw] = hits
        return out

    def match_user_agents(self, values: Iterable[str]) -> dict[str, list[Indicator]]:
        """Each user agent equal to (case-insensitive) or containing an indicator."""
        exact = [i for i in self.indicators if i.kind == "user_agent"]
        subs = [i for i in self.indicators if i.kind == "user_agent_substring"]
        out: dict[str, list[Indicator]] = {}
        for raw in values:
            if not raw:
                continue
            ua = raw.strip().lower()
            hits = [i for i in exact if ua == i.value] + [i for i in subs if i.value in ua]
            if hits:
                out[raw] = hits
        return out

    def url_markers(self) -> list[Indicator]:
        return [i for i in self.indicators if i.kind == "url_marker"]

    def match_domains(self, values: Iterable[str]) -> dict[str, list[Indicator]]:
        """Each domain in ``values`` equal to, or under, a domain indicator."""
        doms = [i for i in self.indicators if i.kind in ("domain", "domain_suffix")]
        out: dict[str, list[Indicator]] = {}
        for raw in values:
            if not raw:
                continue
            d = raw.strip().lower().rstrip(".")
            hits = [i for i in doms if d == i.value or d.endswith("." + i.value)]
            if hits:
                out[raw] = hits
        return out


# ----- loading -------------------------------------------------------------- #

def ioc_paths(raw: str | None) -> list[Path]:
    """Files named by DAWNPATROL_IOC_PATHS (comma-separated files or folders)."""
    entries = [p.strip() for p in (raw or "").split(",") if p.strip()]
    if not entries:
        entries = [DEFAULT_IOC_DIR]
    files: list[Path] = []
    for entry in entries:
        p = Path(entry)
        if p.is_dir():
            files += sorted(f for f in p.iterdir()
                            if f.is_file() and f.suffix.lower() in (".csv", ".txt"))
        elif p.is_file():
            files.append(p)
    return files


def load_iocs(paths: Iterable[Path], today: date | None = None) -> IocSet:
    today = today or datetime.now(UTC).date()
    result = IocSet()
    seen: dict[tuple[str, str], Indicator] = {}
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            log.warning("IoC list %s unreadable: %s", path, exc)
            continue
        result.files.append(path.name)
        rows = _csv_rows(text) if path.suffix.lower() == ".csv" else _text_rows(text)
        for row in rows:
            for ind in _indicators(row, path.name, result):
                if ind.expires and ind.expires < today:
                    result.expired += 1
                    continue
                key = (ind.kind, ind.value)
                # The same value in two lists keeps the higher severity.
                if key not in seen or ind.severity > seen[key].severity:
                    seen[key] = ind
    result.indicators = list(seen.values())
    return result


def _csv_rows(text: str) -> list[dict[str, str]]:
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return []
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            for row in reader]


def _text_rows(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            rows.append({"indicator": line})
    return rows


def refang(value: str) -> str:
    v = value.strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[:]", ":"),
                 ("hxxps://", "https://"), ("hxxp://", "http://")):
        v = v.replace(a, b)
    return v


def _indicators(row: dict[str, str], origin: str, result: IocSet) -> list[Indicator]:
    raw = (row.get("indicator") or row.get("value") or row.get("ioc") or "").strip()
    declared = (row.get("type") or "").strip().lower()
    kind = _TYPE_ALIASES.get(declared) if declared else _infer(refang(raw))
    if declared and kind is None:
        result.skipped_types[declared] = result.skipped_types.get(declared, 0) + 1
        return []
    tier = (row.get("tier") or "").strip().upper()
    if kind in ("user_agent", "user_agent_substring") and tier == "T4":
        # Generic user agents (curl, python-requests, bare Mozilla/5.0): the
        # lists that carry them say never to act on them alone.
        label = f"{declared} (T4, enrichment only)"
        result.skipped_types[label] = result.skipped_types.get(label, 0) + 1
        return []
    if kind == "url_marker":
        values = _marker_variants(raw)
    elif kind in TEXT_KINDS:
        values = [raw.lower()] if len(raw) >= MIN_TEXT_MARKER else []
    else:
        values = [v for v in [_normalize(refang(raw), kind)] if v is not None]
    if not values:
        result.invalid += 1
        return []
    return [ind for v in values if (ind := _build(row, v, kind, tier, origin))]


def _marker_variants(raw: str) -> list[str]:
    """A string-marker cell can list variants: "artx_* / artx-* / zzartx<n>.php".
    Wildcards and placeholders reduce to the literal part; parts shorter than
    MIN_TEXT_MARKER are dropped as too likely to match by accident."""
    out = []
    for part in raw.split(" / "):
        part = re.sub(r"\(.*?\)", "", part).strip().strip("*").split("<", 1)[0]
        part = part.split("*", 1)[0].strip()
        if len(part) >= MIN_TEXT_MARKER:
            out.append(part.lower())
    return out


def _build(row: dict[str, str], value: str, kind: str, tier: str,
           origin: str) -> Indicator | None:
    if kind == "ip" and "/" in value:
        kind = "cidr"

    if tier in _TIER_SEVERITY:
        severity = _TIER_SEVERITY[tier]
    else:
        try:
            severity = Severity.parse(row["severity"]) if row.get("severity") else Severity.LOW
        except ValueError:
            severity = Severity.LOW
        severity = max(Severity.INFO, severity)
    return Indicator(
        value=value, kind=kind, severity=severity, tier=tier if tier in _TIER_SEVERITY else "",
        source=_cap(row.get("source", "")), campaign=_cap(row.get("campaign", "")),
        warning=_cap(row.get("warning") or row.get("notes") or ""),
        expires=_date(row.get("alert_until") or row.get("valid_until") or row.get("expires")),
        origin=origin,
    )


def _infer(raw: str) -> str | None:
    if raw.startswith(("*.", ".")):
        return "domain_suffix"
    try:
        ipaddress.ip_network(raw, strict=False)
        return "cidr" if "/" in raw else "ip"
    except ValueError:
        return "domain"


def _normalize(raw: str, kind: str | None) -> str | None:
    if kind in ("ip", "cidr"):
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
                floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
                if net.prefixlen < floor:
                    return None
                return str(net)
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None
    if kind in ("domain", "domain_suffix"):
        d = raw.lower().removeprefix("*.").lstrip(".").rstrip(".")
        d = re.sub(r"^[a-z]+://", "", d).split("/", 1)[0].split(":", 1)[0]
        return d if _DOMAIN_RE.match(d) else None
    return None


def _date(text: str | None) -> date | None:
    if not text:
        return None
    try:
        return date.fromisoformat(text.strip()[:10])
    except ValueError:
        return None


def _cap(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _TEXT_CAP else text[:_TEXT_CAP - 3] + "..."
