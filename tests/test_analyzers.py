"""Analyzers are tested against synthetic data with known planted patterns.

Each test asserts a specific detection the analyzer is supposed to make, and
several assert the equally important negative: that benign shapes are NOT
reported.
"""

from __future__ import annotations

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.beaconing import BeaconingAnalyzer, beacon_score
from dawnpatrol.analyzers.correlation import CorrelationAnalyzer
from dawnpatrol.analyzers.dns_anomalies import DNSAnomalyAnalyzer, looks_like_dga
from dawnpatrol.analyzers.firewall_patterns import FirewallPatternAnalyzer
from dawnpatrol.analyzers.firewall_volume import FirewallVolumeAnalyzer
from dawnpatrol.analyzers.segment_review import SegmentReviewAnalyzer
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
                     SegmentReviewAnalyzer(), CorrelationAnalyzer()):
        result = analyzer.run(q, profile, b)
        assert result.error is None
