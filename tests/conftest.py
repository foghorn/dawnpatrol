"""Shared fixtures. Everything here runs offline - no network, no API keys."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dawnpatrol.config import (
    AISettings,
    DatabaseSettings,
    RetentionSettings,
    ScheduleSettings,
    Settings,
)
from dawnpatrol.models import UTC, Event, EventKind, Window
from dawnpatrol.profile import Profile
from dawnpatrol.secrets import SecretRegistry
from dawnpatrol.store import Store

PROFILE_YAML = """
site:
  name: testnet
  timezone: UTC

zones:
  - name: lan
    cidrs: ["10.10.0.0/24"]
    trust: trusted
  - name: iot
    cidrs: ["10.10.50.0/24"]
    trust: untrusted
    gateway: "10.10.0.8"
    notes: Cameras and sensors.
    expected_egress_domains: ["vendor.example"]
  - name: dmz
    cidrs: ["10.10.15.0/24"]
    trust: semi-trusted
    gateway: "10.10.0.2"

hosts:
  - { ip: "10.10.0.1", role: router, name: edge }
  - { ip: "10.10.0.69", role: dns-resolver, authoritative_resolver: true }

policy:
  approved_resolvers: ["10.10.0.69"]
  attack_surface_ports: [22, 23, 445, 3389]
  nat_attribution_limited_behind: ["10.10.0.8", "10.10.0.2"]

known_quirks:
  - "Client 10.10.0.211 emits malformed mDNS names."
"""


@pytest.fixture
def profile(tmp_path: Path) -> Profile:
    path = tmp_path / "profile.yml"
    path.write_text(PROFILE_YAML, encoding="utf-8")
    return Profile.load(path)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "out"
    data_dir.mkdir()
    out_dir.mkdir()
    return Settings(
        data_dir=data_dir,
        output_dir=out_dir,
        profile_path=None,
        window_hours=24,
        db=DatabaseSettings(url=f"sqlite:///{data_dir/'test.db'}", dialect="sqlite",
                            display="sqlite (test)"),
        ai=AISettings(enabled=False),
        schedule=ScheduleSettings(),
        retention=RetentionSettings(),
        secrets=SecretRegistry(),
    )


@pytest.fixture
def store(settings: Settings) -> Store:
    s = Store(settings.db, settings.retention)
    s.create_all()
    yield s
    s.dispose()


@pytest.fixture
def window() -> Window:
    end = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    return Window(start=end - timedelta(hours=24), end=end)


def make_events(window: Window, profile: Profile, seed: int = 7) -> list[Event]:
    """A synthetic day with known, deliberately-planted patterns.

    Contains: background scanner sweep, one persistent SSH prober, conntrack
    return traffic, ordinary DNS, a resolver-bypass attempt, and a periodic
    beacon. Analyzers are tested against these known answers.
    """
    rng = random.Random(seed)
    events: list[Event] = []
    start = window.start

    def zones(**kw):
        out = dict(kw)
        out["src_zone"] = profile.zone_of(out.get("src_ip") or out.get("client_ip"))
        out["dst_zone"] = profile.zone_of(out.get("dst_ip"))
        return out

    # 1. Mass scanner sweep: 40 addresses in one /24, ~1 hit each.
    for i in range(40):
        events.append(Event(
            ts=start + timedelta(minutes=rng.randint(0, 1400)),
            source="synthetic", kind=EventKind.FIREWALL,
            dedup_key=f"synthetic:sweep{i}", action="drop", proto="tcp",
            src_port=rng.randint(1024, 65000), dst_port=rng.choice([80, 443, 8080, 22]),
            ttl=rng.randint(45, 55), pkt_len=60, iface_in="eth0",
            **zones(src_ip=f"198.51.100.{i + 1}", dst_ip="203.0.113.10"),
        ))

    # 2. Persistent prober: one source, port 22, sustained for 8 hours.
    for i in range(300):
        events.append(Event(
            ts=start + timedelta(hours=2) + timedelta(seconds=96 * i),
            source="synthetic", kind=EventKind.FIREWALL,
            dedup_key=f"synthetic:prober{i}", action="drop", proto="tcp",
            src_port=rng.randint(40000, 60000), dst_port=22,
            ttl=51, pkt_len=60, iface_in="eth0",
            **zones(src_ip="203.0.113.45", dst_ip="203.0.113.10"),
        ))

    # 3. Conntrack return traffic: TCP from sport 443. Benign by construction.
    for i in range(60):
        events.append(Event(
            ts=start + timedelta(minutes=rng.randint(0, 1400)),
            source="synthetic", kind=EventKind.FIREWALL,
            dedup_key=f"synthetic:return{i}", action="drop", proto="tcp",
            src_port=443, dst_port=rng.randint(40000, 65000),
            ttl=57, pkt_len=1500, iface_in="eth0",
            **zones(src_ip=f"93.184.216.{rng.randint(1, 30)}", dst_ip="203.0.113.10"),
        ))

    # 4. Ordinary DNS from LAN clients.
    domains = ["example.com", "cdn.example.com", "vendor.example", "news.example.org"]
    for i in range(500):
        events.append(Event(
            ts=start + timedelta(seconds=rng.randint(0, 86000)),
            source="synthetic", kind=EventKind.DNS,
            dedup_key=f"synthetic:dns{i}",
            domain=rng.choice(domains), qtype="A",
            blocked=rng.random() < 0.2,
            block_reason="GRAVITY" if rng.random() < 0.2 else None,
            **zones(client_ip=f"10.10.0.{rng.randint(20, 60)}"),
        ))

    # 5. Resolver bypass: a LAN host talking to an external resolver on port 53.
    for i in range(25):
        events.append(Event(
            ts=start + timedelta(minutes=rng.randint(0, 1400)),
            source="synthetic", kind=EventKind.FIREWALL,
            dedup_key=f"synthetic:bypass{i}", action="accept", proto="udp",
            src_port=rng.randint(30000, 60000), dst_port=53, iface_in="br0",
            **zones(src_ip="10.10.0.55", dst_ip="8.8.8.8"),
        ))

    # 6. A real beacon: exactly every 10 minutes for 12 hours.
    for i in range(72):
        events.append(Event(
            ts=start + timedelta(minutes=10 * i),
            source="synthetic", kind=EventKind.DNS,
            dedup_key=f"synthetic:beacon{i}",
            domain="steady-checkin.example.net", qtype="A", blocked=False,
            **zones(client_ip="10.10.0.99"),
        ))

    return events
