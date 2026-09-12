"""Source parsing and the failure modes that previously caused silent data loss."""

from __future__ import annotations

from datetime import datetime

import pytest

from dawnpatrol.models import UTC, EventKind
from dawnpatrol.sources.librenms_syslog import (
    LibreNMSSyslogSource,
    _parse_timestamp,
    _severity_name,
)
from dawnpatrol.sources.pihole_dns import BLOCKED_STATUSES, PiholeDNSSource


@pytest.fixture
def librenms(profile):
    s = LibreNMSSyslogSource()
    s.configure(profile)
    return s


@pytest.fixture
def pihole(profile):
    s = PiholeDNSSource()
    s.configure(profile)
    return s


# --------------------------------------------------------------------------- #
# LibreNMS parsing
# --------------------------------------------------------------------------- #


def test_iptables_drop_line_is_parsed(librenms):
    entry = {
        "timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": 1, "level": 4,
        "msg": ("DROP IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.45 DST=198.51.100.9 "
                "LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=1234 PROTO=TCP SPT=54321 DPT=22"),
    }
    ev = librenms._normalize(entry, "3")
    assert ev.kind == EventKind.FIREWALL
    assert ev.action == "drop"
    assert ev.src_ip == "203.0.113.45"
    assert ev.dst_port == 22
    assert ev.src_port == 54321
    assert ev.proto == "tcp"
    assert ev.ttl == 51
    assert ev.iface_in == "eth0"


def test_numeric_protocol_is_normalized(librenms):
    """PROTO arrives as a raw number on some firmware; unified names keep
    protocol breakdowns from fragmenting."""
    entry = {"timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": 2,
             "msg": "DROP IN=br0 SRC=10.10.0.5 DST=224.0.0.1 LEN=32 TTL=1 PROTO=2"}
    assert librenms._normalize(entry, "3").proto == "igmp"


def test_vpn_program_becomes_an_auth_event(librenms):
    entry = {"timestamp": "2026-06-01 03:14:15", "program": "VPNSERVER1", "seq": 3,
             "msg": "peer 198.51.100.7 authenticated"}
    assert librenms._normalize(entry, "3").kind == EventKind.AUTH


def test_non_firewall_program_becomes_a_system_event(librenms):
    entry = {"timestamp": "2026-06-01 03:14:15", "program": "DNSMASQ-DHCP", "seq": 4,
             "msg": "DHCPACK(br0) 10.10.0.55"}
    assert librenms._normalize(entry, "3").kind == EventKind.SYSTEM


def test_unparseable_timestamp_is_dropped_not_guessed(librenms):
    assert librenms._normalize({"timestamp": "not a date", "msg": "x"}, "3") is None


@pytest.mark.parametrize("raw,expected", [
    ("2026-06-01 03:14:15", datetime(2026, 6, 1, 3, 14, 15, tzinfo=UTC)),
    ("2026-06-01T03:14:15", datetime(2026, 6, 1, 3, 14, 15, tzinfo=UTC)),
    ("2026-06-01 03:14:15.123", datetime(2026, 6, 1, 3, 14, 15, tzinfo=UTC)),
    ("2026-06-01", datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)),
])
def test_timestamp_formats(raw, expected):
    assert _parse_timestamp(raw) == expected


def test_severity_numbers_map_to_names():
    assert _severity_name(0) == "emerg"
    assert _severity_name(6) == "info"
    assert _severity_name("warning") == "warning"


def test_emerg_noise_is_contextualised_not_alarming(librenms, window):
    """Consumer firmware mislabels routine chatter as 'emerg'. The health note
    must break it down by program rather than let the count speak for itself."""
    from dawnpatrol.models import CollectionResult, Event

    events = [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.SYSTEM,
              dedup_key=f"k{i}", severity="emerg", program="ROAMAST", message="x")
        for i in range(50)
    ]
    notes = librenms.extra_health_notes(
        CollectionResult(source="librenms_syslog", events=events))
    assert notes and "ROAMAST=50" in notes[0]
    assert "not a severity signal" in notes[0]


def test_windowed_urls_use_string_dates_never_epoch(librenms, window):
    """Epoch integers return HTTP 200 with total=0 - a silent failure that looks
    exactly like a dead feed."""
    assert window.start_str == window.start.strftime("%Y-%m-%d %H:%M:%S")
    assert not window.start_str.isdigit()


# --------------------------------------------------------------------------- #
# Pi-hole parsing
# --------------------------------------------------------------------------- #


def test_blocked_statuses_cover_more_than_gravity():
    """Filtering only for GRAVITY materially understates the block rate."""
    for status in ("GRAVITY", "GRAVITY_CNAME", "DENYLIST", "REGEX", "SPECIAL_DOMAIN"):
        assert status in BLOCKED_STATUSES


def test_query_normalization(pihole):
    ev = pihole._normalize({
        "id": 42, "time": 1780000000.0, "domain": "Ads.Example.COM.",
        "type": "A", "status": "GRAVITY", "client": {"ip": "10.10.0.55"},
    })
    assert ev.kind == EventKind.DNS
    assert ev.domain == "ads.example.com"   # normalized case and trailing dot
    assert ev.blocked is True
    assert ev.block_reason == "GRAVITY"
    assert ev.client_ip == "10.10.0.55"


def test_allowed_query_is_not_marked_blocked(pihole):
    ev = pihole._normalize({"id": 43, "time": 1780000000.0, "domain": "example.com",
                            "status": "FORWARDED", "client": "10.10.0.60"})
    assert ev.blocked is False
    assert ev.client_ip == "10.10.0.60"


def test_in_progress_queries_are_excluded(pihole):
    """Transient rows would otherwise distort the block-rate denominator."""
    assert pihole._normalize({"id": 44, "time": 1780000000.0, "domain": "x.com",
                              "status": "IN_PROGRESS"}) is None


def test_malformed_records_are_dropped_not_fatal(pihole):
    assert pihole._normalize({"id": 45, "domain": "x.com"}) is None
    assert pihole._normalize({"id": 46, "time": "garbage", "domain": "x.com"}) is None


def test_decoding_tolerates_non_utf8_bytes():
    """A poison mDNS record must not abort a 200,000-record pull."""
    import httpx

    from dawnpatrol.sources.pihole_dns import _decode

    body = b'{"queries":[{"id":1,"domain":"lb._dns-sd._udp.\xc0\x01\x02"}]}'
    data = _decode(httpx.Response(200, content=body))
    assert data["queries"][0]["id"] == 1


def test_retention_ceiling_is_declared(pihole):
    assert pihole.max_window_hours == 24


def test_window_is_clamped_to_retention(pihole, window):
    from dawnpatrol.models import Window
    from datetime import timedelta
    long_window = Window(start=window.end - timedelta(hours=48), end=window.end)
    assert pihole.effective_window(long_window).hours == 24


def test_control_characters_are_stripped_from_domains(pihole):
    """Bytes that survive tolerant decoding must never reach the database."""
    ev = pihole._normalize({
        "id": 47, "time": 1780000000.0,
        "domain": "lb._dns-sd._udp.�\x01\x02", "status": "FORWARDED",
    })
    assert ev.domain == "lb._dns-sd._udp."[:-1] or ev.domain == "lb._dns-sd._udp"
    assert all(c.isprintable() for c in ev.domain)
