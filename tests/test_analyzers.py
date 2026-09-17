"""Analyzers are tested against synthetic data with known planted patterns.

Each test asserts a specific detection the analyzer is supposed to make, and
several assert the equally important negative: that benign shapes are NOT
reported.
"""

from __future__ import annotations

import pytest

from dawnpatrol.analyzers.auth_activity import AuthActivityAnalyzer
from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.beaconing import BeaconingAnalyzer, beacon_score
from dawnpatrol.analyzers.correlation import CorrelationAnalyzer
from dawnpatrol.analyzers.dns_anomalies import DNSAnomalyAnalyzer, looks_like_dga
from dawnpatrol.analyzers.firewall_patterns import FirewallPatternAnalyzer
from dawnpatrol.analyzers.firewall_volume import FirewallVolumeAnalyzer
from dawnpatrol.analyzers.novel_clients import NovelClientAnalyzer
from dawnpatrol.analyzers.segment_review import SegmentReviewAnalyzer
from dawnpatrol.models import EntityType, Metric
from dawnpatrol.query import EventQuery
from tests.conftest import make_events

RUN = "testrun"


@pytest.fixture
def q(store, profile, window):
    store.start_run(RUN, 1, window.start, window)
    store.insert_events(RUN, make_events(window, profile))
    return EventQuery(store, RUN)


@pytest.fixture
def baseline(store):
    return Baseline(store, RUN)


def taxonomies(result):
    return {s.taxonomy for s in result.signals}


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #


def test_volume_metrics_are_computed(q, profile, baseline):
    result = FirewallVolumeAnalyzer().run(q, profile, baseline)
    keys = {m.key for m in result.metrics}
    assert "fw.total" in keys
    assert "fw.drops" in keys
    assert "fw.unique_sources" in keys
    drops = next(m for m in result.metrics if m.key == "fw.drops")
    assert drops.value == 400  # 40 sweep + 300 prober + 60 return


def test_persistent_prober_is_detected(q, profile, baseline):
    result = FirewallPatternAnalyzer().run(q, profile, baseline)
    probers = [s for s in result.signals if s.taxonomy == "scan.persistent_prober"]
    assert len(probers) == 1
    signal = probers[0]
    assert signal.evidence["top_port"] == 22
    assert signal.evidence["targets_attack_surface_port"] is True
    assert signal.evidence["duration_hours"] > 2
    assert any(e.value == "203.0.113.45" for e in signal.entities)


def test_scanner_sweep_is_classified_as_noise(q, profile, baseline):
    result = FirewallPatternAnalyzer().run(q, profile, baseline)
    sweeps = [s for s in result.signals if s.taxonomy == "scan.mass_sweep"]
    assert sweeps, "the 198.51.100.0/24 sweep should be recognised"
    assert sweeps[0].severity_hint.name == "INFO"
    assert sweeps[0].evidence["distinct_sources"] >= 15


def test_conntrack_return_traffic_is_not_a_prober(q, profile, baseline):
    """The benign shape must not be reported. This is the false-positive guard."""
    result = FirewallPatternAnalyzer().run(q, profile, baseline)
    probers = [s for s in result.signals if s.taxonomy == "scan.persistent_prober"]
    for signal in probers:
        assert not any(e.value.startswith("93.184.216.") for e in signal.entities)
    assert any(m.key == "fw.conntrack_return" for m in result.metrics)


def test_sweep_members_are_not_double_reported(q, profile, baseline):
    result = FirewallPatternAnalyzer().run(q, profile, baseline)
    prober_ips = {
        e.value for s in result.signals if s.taxonomy == "scan.persistent_prober"
        for e in s.entities
    }
    assert not any(ip.startswith("198.51.100.") for ip in prober_ips)


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def test_dns_metrics_and_block_rate(q, profile, baseline):
    result = DNSAnomalyAnalyzer().run(q, profile, baseline)
    keys = {m.key: m.value for m in result.metrics}
    assert keys["dns.total"] == 572  # 500 ordinary + 72 beacon
    assert 0 <= keys["dns.block_rate"] <= 100


def test_resolver_bypass_is_high_severity(q, profile, baseline):
    result = DNSAnomalyAnalyzer().run(q, profile, baseline)
    bypass = [s for s in result.signals if s.taxonomy == "dns.resolver_bypass"]
    assert bypass, "a LAN host querying 8.8.8.8 should be flagged"
    assert bypass[0].severity_hint.name == "HIGH"
    assert "8.8.8.8" in str(bypass[0].evidence)


def test_nxdomain_outlier_client_is_flagged(q, profile, baseline, window):
    from dawnpatrol.models import Event, EventKind

    events = []
    # Outlier: 150 of 250 queries are NXDOMAIN (60%).
    for i in range(250):
        events.append(Event(
            ts=window.end, source="pihole_dns", kind=EventKind.DNS,
            dedup_key=f"nx-out-{i}", client_ip="10.10.0.150", src_zone="lan",
            domain=f"candidate{i}.example.net", blocked=False,
            block_reason="NXDOMAIN" if i < 150 else "FORWARDED",
        ))
    # Peer: 35 of 250 are NXDOMAIN (14%) - a real but much lower rate.
    for i in range(250):
        events.append(Event(
            ts=window.end, source="pihole_dns", kind=EventKind.DNS,
            dedup_key=f"nx-peer-{i}", client_ip="10.10.0.151", src_zone="lan",
            domain=f"peer{i}.example.net", blocked=False,
            block_reason="NXDOMAIN" if i < 35 else "FORWARDED",
        ))
    q.store.insert_events(q.run_id, events)
    result = DNSAnomalyAnalyzer().run(q, profile, baseline)
    outlier = [s for s in result.signals if s.taxonomy == "dns.nxdomain_outlier"]
    assert any(s.evidence["client"] == "10.10.0.150" for s in outlier)
    assert not any(s.evidence["client"] == "10.10.0.151" for s in outlier)


def test_low_nxdomain_count_is_not_flagged_regardless_of_rate(q, profile, baseline, window):
    """A handful of NXDOMAIN responses (mDNS probing, a typo) is not a DGA -
    the absolute floor matters as much as the rate."""
    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end, source="pihole_dns", kind=EventKind.DNS,
              dedup_key=f"nx-low-{i}", client_ip="10.10.0.152", src_zone="lan",
              domain=f"x{i}.example.net", blocked=False,
              block_reason="NXDOMAIN" if i < 5 else "FORWARDED")
        for i in range(250)
    ]
    q.store.insert_events(q.run_id, events)
    result = DNSAnomalyAnalyzer().run(q, profile, baseline)
    assert not any(s.taxonomy == "dns.nxdomain_outlier"
                  and s.evidence["client"] == "10.10.0.152" for s in result.signals)


@pytest.mark.parametrize("domain,expected", [
    ("kq3xzmv9rwptnb42.example.com", True),
    ("x7f2k9qz1mw8vnp3.badsite.net", True),
    ("documentation.example.com", False),
    ("cdn.example.com", False),
    ("mail.google.com", False),
])
def test_dga_heuristic(domain, expected):
    suspicious, _entropy, _label = looks_like_dga(domain)
    assert suspicious is expected


# --------------------------------------------------------------------------- #
# Beaconing
# --------------------------------------------------------------------------- #


def test_beacon_score_detects_regular_interval():
    stamps = [float(i * 300) for i in range(60)]
    score = beacon_score(stamps)
    assert score is not None
    assert score["interval_seconds"] == pytest.approx(300, abs=1)
    assert score["cv"] < 0.01


def test_beacon_score_rejects_irregular_traffic():
    import random
    rng = random.Random(3)
    stamps, t = [], 0.0
    for _ in range(60):
        t += rng.uniform(10, 3000)
        stamps.append(t)
    assert beacon_score(stamps) is None


def test_beacon_score_rejects_too_few_samples():
    assert beacon_score([float(i * 300) for i in range(5)]) is None


def test_planted_beacon_is_found(q, profile, baseline):
    result = BeaconingAnalyzer().run(q, profile, baseline)
    beacons = [s for s in result.signals if s.taxonomy == "c2.beacon_candidate"]
    assert beacons, "the 10-minute beacon should be detected"
    signal = beacons[0]
    assert signal.evidence["interval_seconds"] == pytest.approx(600, abs=5)
    assert signal.evidence["client"] == "10.10.0.99"


def test_beaconing_notes_missing_flow_source(q, profile, baseline):
    result = BeaconingAnalyzer().run(q, profile, baseline)
    assert any("flow source" in n for n in result.notes)


# --------------------------------------------------------------------------- #
# Segments and correlation
# --------------------------------------------------------------------------- #


def test_segment_review_emits_nat_caveat(q, profile, baseline):
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    assert any("attribution" in n.lower() for n in result.notes)


def test_segment_metrics_cover_every_zone(q, profile, baseline):
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    keys = {m.key for m in result.metrics}
    for zone in ("lan", "iot", "dmz"):
        assert f"zone.{zone}.dns" in keys


# --------------------------------------------------------------------------- #
# Time-of-day baselining per zone
# --------------------------------------------------------------------------- #


def test_daypart_metrics_are_always_recorded(q, profile, baseline):
    """The metric is recorded every run regardless of whether enough history
    exists yet to judge it - that history has to come from somewhere."""
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    keys = {m.key for m in result.metrics}
    for part in ("night", "morning", "afternoon", "evening"):
        assert f"zone.iot.daypart.{part}" in keys


def test_daypart_anomaly_fires_for_activity_in_a_normally_quiet_window(store, profile, window):
    from datetime import datetime, timedelta

    from dawnpatrol.models import UTC, Event, EventKind, Metric

    run_id = "daypart-quiet-then-active"
    # Store.metric_history() filters against real wall-clock time, not the
    # fictional test `window` - history must be seeded relative to "now".
    real_now = datetime.now(UTC)
    for day in range(1, 7):
        store.save_metrics(run_id, real_now - timedelta(days=day),
                           [Metric(key="zone.iot.daypart.night", value=0,
                                  section="segments_time")])
    store.start_run(run_id, 1, window.start, window)

    night_ts = datetime(window.end.year, window.end.month, window.end.day, 2, 0,
                        tzinfo=UTC)
    events = [
        Event(ts=night_ts, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key=f"night{i}", action="drop", src_ip=f"10.10.50.{i}",
              dst_ip="203.0.113.10", src_zone="iot", dst_zone="external")
        for i in range(25)
    ]
    store.insert_events(run_id, events)
    result = SegmentReviewAnalyzer().run(
        EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert any(s.taxonomy == "segment.time_of_day_anomaly"
              and s.evidence["zone"] == "iot" and s.evidence["daypart"] == "night"
              for s in result.signals)


def test_daypart_anomaly_does_not_fire_without_enough_history(store, profile, window):
    from datetime import datetime

    from dawnpatrol.models import UTC, Event, EventKind

    run_id = "daypart-no-history"
    store.start_run(run_id, 1, window.start, window)
    night_ts = datetime(window.end.year, window.end.month, window.end.day, 2, 0,
                        tzinfo=UTC)
    events = [
        Event(ts=night_ts, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key=f"nohist{i}", action="drop", src_ip=f"10.10.50.{i}",
              dst_ip="203.0.113.10", src_zone="iot", dst_zone="external")
        for i in range(25)
    ]
    store.insert_events(run_id, events)
    result = SegmentReviewAnalyzer().run(
        EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert not any(s.taxonomy == "segment.time_of_day_anomaly" for s in result.signals)


def test_daypart_anomaly_does_not_fire_when_the_hour_is_not_historically_quiet(
    store, profile, window,
):
    """A zone that is genuinely active every night should not be flagged just
    for continuing to be active - only a real shift from its own history."""
    from datetime import datetime, timedelta

    from dawnpatrol.models import UTC, Event, EventKind, Metric

    run_id = "daypart-always-busy"
    real_now = datetime.now(UTC)
    for day in range(1, 7):
        store.save_metrics(run_id, real_now - timedelta(days=day),
                           [Metric(key="zone.iot.daypart.night", value=30,
                                  section="segments_time")])
    store.start_run(run_id, 1, window.start, window)

    night_ts = datetime(window.end.year, window.end.month, window.end.day, 2, 0,
                        tzinfo=UTC)
    events = [
        Event(ts=night_ts, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key=f"busy{i}", action="drop", src_ip=f"10.10.50.{i}",
              dst_ip="203.0.113.10", src_zone="iot", dst_zone="external")
        for i in range(25)
    ]
    store.insert_events(run_id, events)
    result = SegmentReviewAnalyzer().run(
        EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert not any(s.taxonomy == "segment.time_of_day_anomaly" for s in result.signals)


# --------------------------------------------------------------------------- #
# Inbound-accepted: blanket for untrusted zones, novelty-gated for trusted ones
# --------------------------------------------------------------------------- #


def test_untrusted_zone_flags_any_accepted_inbound(q, profile, baseline, window):
    from dawnpatrol.models import Event, EventKind, Severity

    q.store.insert_events(q.run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="ib1", action="accept", src_ip="203.0.113.50", dst_port=8080,
              src_zone="external", dst_zone="iot"),
    ])
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    signal = next(s for s in result.signals if s.taxonomy == "segment.inbound_accepted"
                 and s.evidence["zone"] == "iot")
    assert signal.severity_hint == Severity.HIGH
    assert signal.evidence["novel_sources_only"] is False


def test_trusted_zone_inbound_accept_needs_a_baseline_first(store, profile, window):
    """No prior run means everything looks novel - too noisy to report, so the
    first-ever run must stay silent rather than flag every standing port-forward."""
    from dawnpatrol.models import Event, EventKind

    run_id = "inbound-first-run"
    store.start_run(run_id, 1, window.start, window)
    store.insert_events(run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="ib2", action="accept", src_ip="203.0.113.60", dst_port=25565,
              src_zone="external", dst_zone="lan"),
    ])
    result = SegmentReviewAnalyzer().run(
        EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert not any(s.taxonomy == "segment.inbound_accepted" and s.evidence["zone"] == "lan"
                  for s in result.signals)


def test_trusted_zone_flags_only_a_novel_external_source(store, profile, window):
    from datetime import timedelta

    from dawnpatrol.models import Event, EventKind, Severity

    run_id = "inbound-trusted"
    _with_baseline(store, window, run_id)
    # 203.0.113.61 is a known, standing port-forward peer from a prior run.
    store.observe_entities([(EntityType.IP, "203.0.113.61", 5)], window.start - timedelta(days=30))
    store.insert_events(run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="ib3", action="accept", src_ip="203.0.113.61", dst_port=25565,
              src_zone="external", dst_zone="lan"),
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="ib4", action="accept", src_ip="203.0.113.70", dst_port=25565,
              src_zone="external", dst_zone="lan"),
    ])
    result = SegmentReviewAnalyzer().run(
        EventQuery(store, run_id), profile, Baseline(store, run_id))
    signal = next(s for s in result.signals if s.taxonomy == "segment.inbound_accepted"
                 and s.evidence["zone"] == "lan")
    assert signal.severity_hint == Severity.MEDIUM
    assert signal.evidence["novel_sources_only"] is True
    srcs = {row["src"] for row in signal.evidence["accepted"]}
    assert srcs == {"203.0.113.70"}


def test_segment_firewall_client_count_includes_both_directions(store, profile, window):
    """Many firewalls only log denied traffic. A device that only ever shows up
    as the target of a rejected inbound session (dst_zone, never src_zone) must
    still be counted - otherwise a segment with real, blocked-only traffic
    would still be undercounted the same way a curated device list is."""
    from dawnpatrol.models import Event, EventKind

    run_id = "seg-bidi"
    store.start_run(run_id, 1, window.start, window)
    events = [
        # 10.128.50.209 initiates traffic out of iot (visible as src_ip).
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="e1", action="reject", src_ip="10.128.50.209",
              dst_ip="10.128.10.161", src_zone="iot", dst_zone="lan"),
        # 10.128.50.55 and .56 are only ever the *target* of rejected inbound
        # sessions - never a src_ip anywhere in this run's events.
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="e2", action="drop", src_ip="10.128.10.1",
              dst_ip="10.128.50.55", src_zone="lan", dst_zone="iot"),
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="e3", action="drop", src_ip="203.0.113.9",
              dst_ip="10.128.50.56", src_zone="external", dst_zone="iot"),
    ]
    store.insert_events(run_id, events)
    q = EventQuery(store, run_id)
    baseline = Baseline(store, run_id)
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    by_key = {m.key: m.value for m in result.metrics}
    assert by_key["zone.iot.fw_clients"] == 3


def test_segment_client_counts_are_distinct_not_event_counts(q, profile, baseline):
    """A zone with a real client population must show up here even with no
    curated device inventory behind it - straight from src_ip/client_ip on
    the events themselves, since a NAT gateway's own log still carries the
    real internal client address in SRC=, not just the gateway's."""
    result = SegmentReviewAnalyzer().run(q, profile, baseline)
    by_key = {m.key: m.value for m in result.metrics}
    assert "zone.lan.dns_clients" in by_key
    assert "zone.lan.fw_clients" in by_key
    # make_events() plants DNS from a handful of distinct 10.10.0.x clients -
    # the distinct count must be far smaller than the raw DNS event count.
    assert 0 < by_key["zone.lan.dns_clients"] < by_key["zone.lan.dns"]


def test_correlation_runs_clean_on_synthetic_data(q, profile, baseline):
    result = CorrelationAnalyzer().run(q, profile, baseline)
    assert result.error is None


def test_analyzers_tolerate_an_empty_store(store, profile, window):
    """No source data must never crash an analyzer - it is a normal state."""
    store.start_run("empty", 1, window.start, window)
    q = EventQuery(store, "empty")
    b = Baseline(store, "empty")
    for analyzer in (FirewallVolumeAnalyzer(), FirewallPatternAnalyzer(),
                     DNSAnomalyAnalyzer(), BeaconingAnalyzer(),
                     SegmentReviewAnalyzer(), CorrelationAnalyzer(),
                     AuthActivityAnalyzer(), NovelClientAnalyzer()):
        result = analyzer.run(q, profile, b)
        assert result.error is None


# --------------------------------------------------------------------------- #
# Novel clients: first-ever-seen internal devices
# --------------------------------------------------------------------------- #


def _with_baseline(store, window, run_id: str, run_number: int = 2):
    """Establish has_baseline() == True via a completed prior run."""
    prior_run = f"{run_id}-prior"
    store.start_run(prior_run, run_number - 1, window.start, window)
    store.finish_run(prior_run, finished_at=window.end, status="GREEN", finding_count=0)
    store.save_metrics(prior_run, window.end,
                       [Metric(key="net.novel_clients", value=0, section="general")])
    store.start_run(run_id, run_number, window.start, window)


def test_first_run_reports_no_novel_client_signal(q, profile, baseline, window):
    """Every device looks novel on a fresh deployment - reported as a note,
    not a wall of signals, exactly like _novel_domains handles the same case."""
    from dawnpatrol.models import Event, EventKind

    q.store.insert_events(q.run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="nc1", src_ip="10.10.0.201", action="drop",
              src_zone="lan", dst_zone="external"),
    ])
    result = NovelClientAnalyzer().run(q, profile, baseline)
    assert not any(s.taxonomy == "net.novel_client" for s in result.signals)
    assert any("first run" in n for n in result.notes)


def test_genuinely_new_internal_ip_is_flagged(store, profile, window):
    from dawnpatrol.models import Event, EventKind

    run_id = "novel-new"
    _with_baseline(store, window, run_id)
    store.insert_events(run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="nc2", src_ip="10.10.0.201", action="drop",
              src_zone="lan", dst_zone="external"),
    ])
    result = NovelClientAnalyzer().run(EventQuery(store, run_id), profile, Baseline(store, run_id))
    signal = next(s for s in result.signals if s.taxonomy == "net.novel_client")
    assert signal.evidence["zone"] == "lan"
    assert "10.10.0.201" in signal.evidence["ips"]


def test_iot_zone_novel_device_is_escalated_above_lan(store, profile, window):
    from dawnpatrol.models import Event, EventKind, Severity

    run_id = "novel-iot"
    _with_baseline(store, window, run_id)
    store.insert_events(run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="nc3", src_ip="10.10.50.5", action="drop",
              src_zone="iot", dst_zone="external"),
    ])
    result = NovelClientAnalyzer().run(EventQuery(store, run_id), profile, Baseline(store, run_id))
    signal = next(s for s in result.signals if s.taxonomy == "net.novel_client"
                 and s.evidence["zone"] == "iot")
    assert signal.severity_hint == Severity.MEDIUM


def test_a_previously_seen_ip_is_not_flagged_again(store, profile, window):
    from datetime import timedelta

    from dawnpatrol.models import Event, EventKind

    run_id = "novel-known"
    _with_baseline(store, window, run_id)
    store.observe_entities([(EntityType.IP, "10.10.0.201", 1)], window.start - timedelta(days=30))
    store.insert_events(run_id, [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.FIREWALL,
              dedup_key="nc4", src_ip="10.10.0.201", action="drop",
              src_zone="lan", dst_zone="external"),
    ])
    result = NovelClientAnalyzer().run(EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert not any(s.taxonomy == "net.novel_client" for s in result.signals)


# --------------------------------------------------------------------------- #
# Auth activity: VPN lifecycle + Wi-Fi deauthentication
# --------------------------------------------------------------------------- #


def test_vpn_lifecycle_events_produce_a_metric_not_a_login_claim(q, profile, baseline, window):
    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.AUTH,
              dedup_key=f"vpn{i}", program="VPNSERVER1")
        for i in range(5)
    ]
    q.store.insert_events(q.run_id, events)
    result = AuthActivityAnalyzer().run(q, profile, baseline)
    by_key = {m.key: m.value for m in result.metrics}
    assert by_key["auth.vpn_events"] == 5
    assert any("per-login VPN analysis is not possible" in n for n in result.notes)
    # No baseline in this fixture, so no restart-frequency signal is possible.
    assert not any(s.taxonomy == "auth.vpn_instability" for s in result.signals)


def test_vpn_restart_frequency_signal_when_far_above_baseline(store, profile, window):
    prior_run = "auth-prior-run"
    store.start_run(prior_run, 1, window.start, window)
    store.finish_run(prior_run, finished_at=window.end, status="GREEN", finding_count=0)
    store.save_metrics(prior_run, window.end,
                       [Metric(key="auth.vpn_events", value=10, section="router")])

    run_id = "auth-current-run"
    store.start_run(run_id, 2, window.start, window)
    from dawnpatrol.models import Event, EventKind
    events = [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.AUTH,
              dedup_key=f"vpn{i}", program="VPNSERVER1")
        for i in range(40)
    ]
    store.insert_events(run_id, events)
    result = AuthActivityAnalyzer().run(EventQuery(store, run_id), profile, Baseline(store, run_id))
    assert any(s.taxonomy == "auth.vpn_instability" for s in result.signals)


def test_deauth_outlier_device_is_flagged(q, profile, baseline, window):
    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.AUTH,
              action="deauth", user="aa:aa:aa:aa:aa:aa", dedup_key=f"d{i}")
        for i in range(30)
    ] + [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.AUTH,
              action="deauth", user="bb:bb:bb:bb:bb:bb", dedup_key=f"e{i}")
        for i in range(2)
    ]
    q.store.insert_events(q.run_id, events)
    result = AuthActivityAnalyzer().run(q, profile, baseline)
    assert any(s.taxonomy == "auth.deauth_outlier"
              and s.evidence["mac"] == "aa:aa:aa:aa:aa:aa" for s in result.signals)


def test_evenly_spread_deauths_are_not_flagged_as_an_outlier(q, profile, baseline, window):
    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end, source="librenms_syslog", kind=EventKind.AUTH,
              action="deauth", user=f"aa:aa:aa:aa:aa:{i:02x}", dedup_key=f"d{i}")
        for i in range(30)
    ]
    q.store.insert_events(q.run_id, events)
    result = AuthActivityAnalyzer().run(q, profile, baseline)
    assert not any(s.taxonomy == "auth.deauth_outlier" for s in result.signals)


def test_mass_deauth_burst_is_flagged(q, profile, baseline, window):
    from datetime import timedelta

    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end - timedelta(seconds=i * 10), source="librenms_syslog",
              kind=EventKind.AUTH, action="deauth", user=f"cc:cc:cc:cc:cc:{i:02x}",
              dedup_key=f"burst{i}")
        for i in range(8)
    ]
    q.store.insert_events(q.run_id, events)
    result = AuthActivityAnalyzer().run(q, profile, baseline)
    assert any(s.taxonomy == "auth.mass_deauth_burst" for s in result.signals)


def test_deauths_spread_across_the_day_are_not_a_mass_burst(q, profile, baseline, window):
    from datetime import timedelta

    from dawnpatrol.models import Event, EventKind

    events = [
        Event(ts=window.end - timedelta(hours=i), source="librenms_syslog",
              kind=EventKind.AUTH, action="deauth", user=f"cc:cc:cc:cc:cc:{i:02x}",
              dedup_key=f"spread{i}")
        for i in range(8)
    ]
    q.store.insert_events(q.run_id, events)
    result = AuthActivityAnalyzer().run(q, profile, baseline)
    assert not any(s.taxonomy == "auth.mass_deauth_burst" for s in result.signals)
