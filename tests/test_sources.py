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


def test_openwrt_kernel_uptime_prefixed_line_is_still_parsed_as_firewall(librenms):
    """OpenWrt-based gateways (observed on the DMZ/IoT firewalls in production)
    prefix the action with a bracketed kernel uptime stamp and lowercase it -
    "[4081245.82] drop wan out: IN=...". Before this was handled, every one of
    these lines fell through to a bare SYSTEM event, indistinguishable from
    DHCP chatter and invisible to every firewall-shaped analyzer."""
    entry = {
        "timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": 10, "level": 4,
        "msg": ("[4081245.823274] drop wan out: IN=eth0 OUT=eth1 MAC=d8:3a:dd:6a:6c:2a "
                "SRC=10.128.15.135 DST=10.128.10.90 LEN=52 TTL=127 PROTO=TCP "
                "SPT=53056 DPT=7680"),
    }
    ev = librenms._normalize(entry, "4")
    assert ev.kind == EventKind.FIREWALL
    assert ev.action == "drop"
    assert ev.src_ip == "10.128.15.135"
    assert ev.dst_ip == "10.128.10.90"
    assert ev.dst_port == 7680
    assert ev.proto == "tcp"


def test_openwrt_kernel_uptime_prefixed_reject_is_parsed(librenms):
    entry = {
        "timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": 11,
        "msg": ("[4082607.98] reject wan out: IN=eth0 OUT=eth1 MAC=dc:a6:32:0d:6f:bd "
                "SRC=10.128.50.209 DST=10.128.10.161 LEN=256 TTL=63 PROTO=UDP "
                "SPT=62691 DPT=62743"),
    }
    ev = librenms._normalize(entry, "7")
    assert ev.kind == EventKind.FIREWALL
    assert ev.action == "reject"
    assert ev.proto == "udp"


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
# LibreNMS device selection and directory
# --------------------------------------------------------------------------- #


def _mock_client(handler):
    import httpx
    return httpx.Client(transport=httpx.MockTransport(handler),
                        headers={"X-Auth-Token": "t"})


def test_device_directory_parses_the_devices_endpoint(librenms, monkeypatch):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")

    def handler(request):
        assert request.url.path.endswith("/devices")
        return httpx.Response(200, json={"devices": [
            {"device_id": 3, "hostname": "edge", "ip": "10.10.0.1",
             "hardware": "ASUS RT-AX88U Pro", "os": "asuswrt-merlin",
             "status": 1, "uptime": 123456},
            {"device_id": 8, "hostname": "dmz-windows", "status": 0},
        ]})

    with _mock_client(handler) as client:
        directory = librenms._device_directory(client)
    assert directory["3"]["hostname"] == "edge"
    assert directory["3"]["hardware"] == "ASUS RT-AX88U Pro"
    assert directory["3"]["status"] == "up"
    assert directory["8"]["status"] == "down"


def test_resolve_devices_prefers_an_explicit_list(librenms, monkeypatch):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", "3,4")

    def handler(request):
        return httpx.Response(200, json={"devices": [
            {"device_id": i, "hostname": f"h{i}"} for i in range(1, 13)
        ]})

    with _mock_client(handler) as client:
        devices, directory = librenms._resolve_devices(client)
    assert devices == ["3", "4"]
    # The directory is still fetched for metadata even when it isn't used to
    # pick which devices to collect from.
    assert len(directory) == 12


def test_resolve_devices_discovers_every_device_when_unset(librenms, monkeypatch):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.delenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", raising=False)

    def handler(request):
        return httpx.Response(200, json={"devices": [
            {"device_id": i, "hostname": f"h{i}"} for i in (3, 1, 12, 7)
        ]})

    with _mock_client(handler) as client:
        devices, directory = librenms._resolve_devices(client)
    assert devices == ["1", "3", "7", "12"]  # numeric order, not string order
    assert len(directory) == 4


def test_resolve_devices_directory_failure_is_not_fatal_with_an_explicit_list(librenms, monkeypatch):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", "3")

    def handler(request):
        return httpx.Response(500)

    with _mock_client(handler) as client:
        devices, directory = librenms._resolve_devices(client)
    assert devices == ["3"]
    assert directory == {}


def test_collect_health_notes_carry_device_metadata_when_available(librenms, monkeypatch, window):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_TOKEN", "tok")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", "3")

    def handler(request):
        if request.url.path.endswith("/devices"):
            return httpx.Response(200, json={"devices": [
                {"device_id": 3, "hostname": "edge", "hardware": "ASUS RT-AX88U Pro",
                 "os": "asuswrt-merlin", "status": 1},
            ]})
        return httpx.Response(200, json={"total": 1, "logs": [
            {"timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": 1,
             "msg": "DROP IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 LEN=60 TTL=51 PROTO=TCP DPT=22"},
        ]})

    monkeypatch.setattr(librenms, "_client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                            headers=librenms._headers()))
    result = librenms.collect(window, ctx=None)
    assert any("edge=1" in n for n in result.notes)


def test_collect_notes_are_a_single_summary_not_one_per_device(librenms, monkeypatch, window):
    """Regression test: a per-device note list is exactly what every renderer's
    SourceHealth.notes[:5-6] truncation silently caps. One summary note must
    cover every device's record count regardless of how many there are."""
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_TOKEN", "tok")
    monkeypatch.delenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", raising=False)

    device_ids = list(range(1, 10))

    def handler(request):
        if request.url.path.endswith("/devices"):
            return httpx.Response(200, json={"devices": [
                {"device_id": i, "hostname": f"h{i}"} for i in device_ids
            ]})
        device_id = int(request.url.path.rsplit("/", 1)[-1])
        # Every other device returns zero records.
        if device_id % 2 == 0:
            return httpx.Response(200, json={"total": 0, "logs": []})
        return httpx.Response(200, json={"total": 1, "logs": [
            {"timestamp": "2026-06-01 03:14:15", "program": "KERNEL", "seq": device_id,
             "msg": "DROP IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 LEN=60 TTL=51 PROTO=TCP DPT=22"},
        ]})

    monkeypatch.setattr(librenms, "_client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                            headers=librenms._headers()))
    result = librenms.collect(window, ctx=None)
    summary = next(n for n in result.notes if n.startswith(f"{len(device_ids)} device(s)"))
    for i in device_ids:
        assert f"h{i}=" in summary
    zero_note = next(n for n in result.notes if "zero records" in n)
    for i in device_ids:
        if i % 2 == 0:
            assert f"h{i}" in zero_note
    # Exactly two notes total, no matter how many devices - never one per device.
    assert len(result.notes) == 2


def test_no_devices_configured_or_discovered_is_a_clear_error(librenms, monkeypatch, window):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_TOKEN", "tok")
    monkeypatch.delenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", raising=False)

    def handler(request):
        return httpx.Response(200, json={"devices": []})

    monkeypatch.setattr(librenms, "_client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                            headers=librenms._headers()))
    result = librenms.collect(window, ctx=None)
    assert not result.events
    assert any("no devices configured" in e for e in result.errors)


# --------------------------------------------------------------------------- #
# Cross-source device directory (dawnpatrol/devices.py)
# --------------------------------------------------------------------------- #


class _FakeCtx:
    """Minimal stand-in for RunContext - collect() only touches ctx.devices."""

    def __init__(self):
        from dawnpatrol.devices import DeviceDirectory
        self.devices = DeviceDirectory()


def test_librenms_collect_registers_devices_by_ip(librenms, monkeypatch, window):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_URL", "http://librenms.example/api/v0")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_TOKEN", "tok")
    monkeypatch.setenv("DAWNPATROL_SOURCE_LIBRENMS_DEVICES", "3")

    def handler(request):
        if request.url.path.endswith("/devices"):
            return httpx.Response(200, json={"devices": [
                {"device_id": 3, "hostname": "edge", "ip": "10.10.0.1",
                 "hardware": "ASUS RT-AX88U Pro", "os": "asuswrt-merlin", "status": 1},
                {"device_id": 8, "hostname": "no-ip-device"},
            ]})
        return httpx.Response(200, json={"total": 0, "logs": []})

    monkeypatch.setattr(librenms, "_client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                            headers=librenms._headers()))
    ctx = _FakeCtx()
    librenms.collect(window, ctx=ctx)

    device = ctx.devices.get("10.10.0.1")
    assert device is not None
    assert device.hostname == "edge"
    assert device.hardware == "ASUS RT-AX88U Pro"
    assert device.status == "up"
    assert "librenms_syslog" in device.sources
    assert "librenms-managed" in device.roles
    # The device with no IP has nothing to key an entry on - it is skipped.
    assert len(ctx.devices) == 1


def test_pihole_collect_registers_dns_clients_by_ip(pihole, monkeypatch, window):
    import httpx

    monkeypatch.setenv("DAWNPATROL_SOURCE_PIHOLE_URL", "http://pihole.example/api")
    monkeypatch.setenv("DAWNPATROL_SOURCE_PIHOLE_PASSWORD", "pw")

    def handler(request):
        if request.url.path.endswith("/auth"):
            return httpx.Response(200, json={"session": {"sid": "s1"}})
        if request.url.path.endswith("/queries"):
            return httpx.Response(200, json={
                "recordsFiltered": 1,
                "queries": [{"id": 1, "time": 1780000000.0, "domain": "example.com",
                            "status": "FORWARDED",
                            "client": {"ip": "10.10.0.55", "name": "kids-ipad"}}],
            })
        return httpx.Response(200, json={})

    monkeypatch.setattr(pihole, "_client",
                        lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    ctx = _FakeCtx()
    pihole.collect(window, ctx=ctx)

    device = ctx.devices.get("10.10.0.55")
    assert device is not None
    assert device.hostname == "kids-ipad"
    assert "pihole_dns" in device.sources
    assert "dns-client" in device.roles


def test_device_directory_merges_across_sources_without_clobbering():
    from dawnpatrol.devices import DeviceDirectory

    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="pihole_dns", role="dns-client")
    devices.update("10.10.0.1", source="librenms_syslog", role="librenms-managed",
                  hostname="edge", hardware="ASUS RT-AX88U Pro")
    # A later, sparser contribution never overwrites a field already filled in.
    devices.update("10.10.0.1", source="librenms_syslog", hostname="should-not-win")

    device = devices.get("10.10.0.1")
    assert device.hostname == "edge"
    assert device.hardware == "ASUS RT-AX88U Pro"
    assert device.sources == {"pihole_dns", "librenms_syslog"}
    assert device.roles == {"dns-client", "librenms-managed"}


def test_device_directory_sorts_numerically_by_ip():
    from dawnpatrol.devices import DeviceDirectory

    devices = DeviceDirectory()
    for ip in ("10.10.0.20", "10.10.0.3", "10.10.0.100"):
        devices.update(ip, source="test")
    assert [d.ip for d in devices.all()] == ["10.10.0.3", "10.10.0.20", "10.10.0.100"]


def test_device_directory_excludes_public_ips_by_default(monkeypatch):
    from dawnpatrol.devices import DeviceDirectory

    monkeypatch.delenv("DAWNPATROL_DEVICES_INCLUDE_PUBLIC_IPS", raising=False)
    devices = DeviceDirectory()
    assert devices.update("75.119.223.77", source="librenms_syslog") is None
    assert devices.get("75.119.223.77") is None
    assert len(devices) == 0
    # Private, loopback, and link-local addresses are never "public".
    devices.update("10.10.0.1", source="librenms_syslog")
    devices.update("127.0.0.1", source="pihole_dns")
    devices.update("169.254.1.1", source="pihole_dns")
    assert len(devices) == 3


def test_device_directory_includes_public_ips_when_opted_in(monkeypatch):
    from dawnpatrol.devices import DeviceDirectory

    monkeypatch.setenv("DAWNPATROL_DEVICES_INCLUDE_PUBLIC_IPS", "true")
    devices = DeviceDirectory()
    devices.update("75.119.223.77", source="librenms_syslog", hostname="example.com")
    assert devices.get("75.119.223.77") is not None
    assert devices.get("75.119.223.77").hostname == "example.com"


def test_device_directory_invalid_ip_is_not_public():
    from dawnpatrol.devices import _is_public

    assert _is_public("not-an-ip") is False


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
    from datetime import timedelta

    from dawnpatrol.models import Window
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
