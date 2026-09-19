"""Site profile: the network topology, loaded from mounted YAML.

This is the file that makes the codebase publishable. Every address, segment,
device role, and local quirk lives here, not in source. The profile is data the
analyzers and the model read; it is never executable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError


@dataclass(slots=True)
class Zone:
    name: str
    cidrs: list[str] = field(default_factory=list)
    trust: str = "unknown"
    gateway: str | None = None
    notes: str = ""
    expected_egress_domains: list[str] = field(default_factory=list)
    _networks: list[Any] = field(default_factory=list, repr=False)

    def compile(self) -> None:
        self._networks = []
        for cidr in self.cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ConfigError(f"zone {self.name!r}: invalid cidr {cidr!r}: {exc}") from exc

    def contains(self, addr: Any) -> bool:
        return any(addr in net for net in self._networks)


@dataclass(slots=True)
class Host:
    ip: str
    role: str = ""
    name: str = ""
    model: str = ""
    notes: str = ""
    authoritative_resolver: bool = False


@dataclass(slots=True)
class Policy:
    wan_ip_is_dynamic: bool = True
    approved_resolvers: list[str] = field(default_factory=list)
    attack_surface_ports: list[int] = field(default_factory=list)
    nat_attribution_limited_behind: list[str] = field(default_factory=list)
    benign_domains: list[str] = field(default_factory=list)
    benign_domain_suffixes: list[str] = field(default_factory=list)
    scanner_isp_hints: list[str] = field(default_factory=list)


DEFAULT_ATTACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1194,
                        1433, 3306, 3389, 5060, 5432, 5900, 8080, 8443, 8728]

DEFAULT_BENIGN_SUFFIXES = [
    "google.com", "gstatic.com", "googleapis.com", "microsoft.com", "windowsupdate.com",
    "apple.com", "icloud.com", "cloudflare.com", "akamai.net", "amazonaws.com",
    "netflix.com", "mozilla.org", "ubuntu.com", "debian.org", "github.com",
    # Meta's CDN legitimately serves many distinct edge hostnames per client
    # (scontent-xyz1-1.fbcdn.net, ...) - confirmed live as a real false
    # positive for dns_anomalies.py's subdomain-fanout tunneling check
    # (one real client crossed 40+ distinct fbcdn.net hostnames at a 0.93
    # uniqueness ratio in ordinary use) before this was added.
    "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "pool.ntp.org", "in-addr.arpa", "ip6.arpa", "local", "arpa",
]


@dataclass(slots=True)
class Profile:
    """Loaded topology. Always constructible - an empty profile is valid."""

    site_name: str = "network"
    timezone: str = "UTC"
    zones: list[Zone] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    policy: Policy = field(default_factory=Policy)
    known_quirks: list[str] = field(default_factory=list)
    source_hints: dict[str, Any] = field(default_factory=dict)
    _host_index: dict[str, Host] = field(default_factory=dict, repr=False)

    # ----- loading --------------------------------------------------------- #

    @classmethod
    def load(cls, path: Path | None) -> Profile:
        if path is None:
            return cls().compiled()
        if not path.is_file():
            raise ConfigError(f"profile not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"profile {path} is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"profile {path} must be a mapping at the top level")
        return cls.from_dict(raw).compiled()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Profile:
        site = raw.get("site") or {}
        zones = []
        for z in raw.get("zones") or []:
            if not z.get("name"):
                raise ConfigError("every zone needs a name")
            zones.append(
                Zone(
                    name=str(z["name"]),
                    cidrs=[str(c) for c in (z.get("cidrs") or [])],
                    trust=str(z.get("trust", "unknown")),
                    gateway=str(z["gateway"]) if z.get("gateway") else None,
                    notes=_clean(z.get("notes", "")),
                    expected_egress_domains=[str(d) for d in (z.get("expected_egress_domains") or [])],
                )
            )
        hosts = [
            Host(
                ip=str(h["ip"]),
                role=str(h.get("role", "")),
                name=str(h.get("name", "")),
                model=str(h.get("model", "")),
                notes=_clean(h.get("notes", "")),
                authoritative_resolver=bool(h.get("authoritative_resolver", False)),
            )
            for h in (raw.get("hosts") or [])
            if h.get("ip")
        ]
        p = raw.get("policy") or {}
        policy = Policy(
            wan_ip_is_dynamic=bool(p.get("wan_ip_is_dynamic", True)),
            approved_resolvers=[str(r) for r in (p.get("approved_resolvers") or [])],
            attack_surface_ports=[int(x) for x in (p.get("attack_surface_ports") or DEFAULT_ATTACK_PORTS)],
            nat_attribution_limited_behind=[
                str(x) for x in (p.get("nat_attribution_limited_behind") or [])
            ],
            benign_domains=[str(x).lower() for x in (p.get("benign_domains") or [])],
            benign_domain_suffixes=[
                str(x).lower() for x in (p.get("benign_domain_suffixes") or DEFAULT_BENIGN_SUFFIXES)
            ],
            scanner_isp_hints=[str(x).lower() for x in (p.get("scanner_isp_hints") or [])],
        )
        return cls(
            site_name=str(site.get("name", "network")),
            timezone=str(site.get("timezone", "UTC")),
            zones=zones,
            hosts=hosts,
            policy=policy,
            known_quirks=[_clean(q) for q in (raw.get("known_quirks") or [])],
            source_hints=raw.get("source_hints") or {},
        )

    def compiled(self) -> Profile:
        for z in self.zones:
            z.compile()
        self._host_index = {h.ip: h for h in self.hosts}
        return self

    # ----- lookups --------------------------------------------------------- #

    def zone_of(self, ip: str | None) -> str | None:
        """Zone name containing ``ip``, else 'external' or 'private'."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for zone in self.zones:
            if zone.contains(addr):
                return zone.name
        return "private" if _is_rfc1918(addr) else "external"

    def zone(self, name: str) -> Zone | None:
        for z in self.zones:
            if z.name == name:
                return z
        return None

    def host(self, ip: str) -> Host | None:
        return self._host_index.get(ip)

    def label_for(self, ip: str | None) -> str:
        """Human label for an address: name, role, or the bare IP."""
        if not ip:
            return "unknown"
        h = self._host_index.get(ip)
        if h is None:
            return ip
        if h.name:
            return f"{ip} ({h.name})"
        if h.role:
            return f"{ip} ({h.role})"
        return ip

    def is_internal(self, ip: str | None) -> bool:
        """On this network, or in RFC1918-style private space."""
        zone = self.zone_of(ip)
        return zone is not None and zone != "external"

    def is_external(self, ip: str | None) -> bool:
        """Not ours. Used by analyzers to decide what counts as an outside party.

        Deliberately broader than :meth:`is_routable`: the documentation ranges
        (RFC 5737 TEST-NET) are not globally routable but are unambiguously not
        part of this network, and the canaries use them precisely because they
        can never collide with real traffic.
        """
        return bool(ip) and self.zone_of(ip) == "external"

    def is_routable(self, ip: str | None) -> bool:
        """Globally routable. The correct gate for an external API lookup.

        Submitting a private or reserved address to a reputation service wastes
        budget a real candidate needed.
        """
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    #: Backwards-compatible alias. Prefer is_external or is_routable - the
    #: distinction between them is load-bearing.
    def is_public(self, ip: str | None) -> bool:
        return self.is_routable(ip)

    def is_benign_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        d = domain.lower().rstrip(".")
        if d in self.policy.benign_domains:
            return True
        return any(d == s or d.endswith("." + s) for s in self.policy.benign_domain_suffixes)

    def nat_limited(self, ip: str | None) -> bool:
        """Whether attribution behind this address is known to be impossible."""
        return bool(ip) and ip in self.policy.nat_attribution_limited_behind

    def attribution_caveat(self, ip: str | None) -> str:
        if not self.nat_limited(ip):
            return ""
        zone = next((z.name for z in self.zones if z.gateway == ip), "that segment")
        return (
            f"Traffic is NATed by the gateway at {ip}, so per-device attribution "
            f"within {zone} is not possible from the current data sources. Reported "
            f"as originating from behind the gateway, not from a specific device."
        )

    # ----- rendering for the model ----------------------------------------- #

    def as_context(self) -> str:
        """Stable text block describing the network. Cached in the prompt prefix.

        Must be deterministic: no timestamps, no counts, nothing that varies
        between runs, or the prompt cache is invalidated every day.
        """
        lines: list[str] = [f"SITE: {self.site_name} (timezone {self.timezone})", ""]
        if self.zones:
            lines.append("NETWORK ZONES")
            for z in self.zones:
                lines.append(f"  {z.name} [{z.trust}] {', '.join(z.cidrs) or '(no cidrs)'}")
                if z.gateway:
                    lines.append(f"    gateway: {z.gateway}")
                if z.expected_egress_domains:
                    lines.append(f"    expected egress: {', '.join(z.expected_egress_domains)}")
                if z.notes:
                    lines.append(f"    notes: {z.notes}")
            lines.append("")
        if self.hosts:
            lines.append("KNOWN HOSTS")
            for h in self.hosts:
                bits = [h.ip]
                if h.name:
                    bits.append(h.name)
                if h.role:
                    bits.append(f"role={h.role}")
                if h.model:
                    bits.append(h.model)
                lines.append("  " + " | ".join(bits))
                if h.notes:
                    lines.append(f"    {h.notes}")
            lines.append("")
        lines.append("POLICY")
        lines.append(f"  WAN address is dynamic: {self.policy.wan_ip_is_dynamic} "
                     f"(a change is not an incident)")
        if self.policy.approved_resolvers:
            lines.append(f"  Approved DNS resolvers: {', '.join(self.policy.approved_resolvers)}")
            lines.append("  Any internal host resolving elsewhere is a policy violation.")
        if self.policy.attack_surface_ports:
            ports = ", ".join(str(p) for p in self.policy.attack_surface_ports)
            lines.append(f"  Attack-surface ports of interest: {ports}")
        if self.policy.nat_attribution_limited_behind:
            gws = ", ".join(self.policy.nat_attribution_limited_behind)
            lines.append(f"  Per-device attribution is impossible behind: {gws}")
        if self.known_quirks:
            lines.append("")
            lines.append("KNOWN LOCAL QUIRKS (established facts, not findings)")
            for q in self.known_quirks:
                lines.append(f"  - {q}")
        return "\n".join(lines)


_RFC1918 = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _is_rfc1918(addr: Any) -> bool:
    return any(addr in net for net in _RFC1918 if addr.version == net.version)


def _clean(value: Any) -> str:
    """Collapse YAML folded whitespace into a single line."""
    return " ".join(str(value or "").split())
