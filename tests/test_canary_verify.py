"""Canary self-validation and source health classification."""

from __future__ import annotations

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.beaconing import BeaconingAnalyzer
from dawnpatrol.analyzers.firewall_patterns import FirewallPatternAnalyzer
from dawnpatrol.canary import CANARY_DOMAIN, CANARY_SRC, CanaryRunner
from dawnpatrol.context import RunContext
from dawnpatrol.models import (
    CollectionResult,
    Event,
    EventKind,
    HealthState,
    Probe,
    Window,
)
from dawnpatrol.query import EventQuery
from dawnpatrol.sources.base import Source
from dawnpatrol.verify import classify

RUN = "canaryrun"


# --------------------------------------------------------------------------- #
# Canaries
# --------------------------------------------------------------------------- #


def test_canaries_are_detected_end_to_end(store, profile, window):
    """The whole point: prove the analyzer chain still detects what it should."""
    runner = CanaryRunner(enabled=True)
    events = runner.inject(window, {EventKind.DNS, EventKind.FIREWALL})
    assert events

    store.start_run(RUN, 1, window.start, window)
    store.insert_events(RUN, events)
    q, b = EventQuery(store, RUN), Baseline(store, RUN)

    signals = []
    for analyzer in (BeaconingAnalyzer(), FirewallPatternAnalyzer()):
        signals.extend(analyzer.run(q, profile, b).signals)

    results = runner.verify(signals)
    assert len(results) == 2
    for result in results:
        assert result.detected, f"canary {result.name} not detected: {result.detail}"


def test_canary_failure_is_reported_not_silent(window):
    runner = CanaryRunner(enabled=True)
    runner.inject(window, {EventKind.DNS, EventKind.FIREWALL})
    results = runner.verify([])   # analyzers produced nothing
    assert results
    assert all(not r.detected for r in results)
    assert all("expected" in r.detail for r in results)


def test_canary_events_use_reserved_ranges_only():
    """They must never collide with, or be mistaken for, real traffic."""
    import ipaddress
    for addr in (CANARY_SRC, "198.51.100.42", "203.0.113.199"):
        assert not ipaddress.ip_address(addr).is_global
    assert CANARY_DOMAIN.endswith(".invalid")


def test_canary_signals_are_excluded_from_the_report(store, profile, window):
    """Canary output must not reach the model or pollute the findings."""
    runner = CanaryRunner(enabled=True)
    events = runner.inject(window, {EventKind.DNS, EventKind.FIREWALL})
    store.start_run(RUN, 1, window.start, window)
    store.insert_events(RUN, events)
    q, b = EventQuery(store, RUN), Baseline(store, RUN)

    results = [a.run(q, profile, b) for a in (BeaconingAnalyzer(), FirewallPatternAnalyzer())]
    runner.mark_signals(results)
    all_signals = [s for r in results for s in r.signals]
    assert all_signals
    assert all(s.is_canary for s in all_signals)

    from dawnpatrol.agent.bundle import _rank_signals
    assert _rank_signals(all_signals) == []


def test_disabled_canary_runner_injects_nothing(window):
    assert CanaryRunner(enabled=False).inject(window, {EventKind.DNS}) == []


# --------------------------------------------------------------------------- #
# Health classification
# --------------------------------------------------------------------------- #


class FakeSource(Source):
    name = "fake"
    kinds = frozenset({EventKind.FIREWALL})

    def __init__(self, probes=None, max_hours=None):
        super().__init__()
        self._probes = probes or []
        self.max_window_hours = max_hours

    def collect(self, window, ctx):
        return CollectionResult(source=self.name)

    def self_test(self, ctx):
        return self._probes


@pytest.fixture
def ctx(settings, profile, store, window):
    return RunContext(run_id=RUN, started_at=window.end, window=window,
                      settings=settings, profile=profile, store=store)


def full_result(window, n=100):
    step = (window.end - window.start) / n
    events = [
        Event(ts=window.start + step * i, source="fake", kind=EventKind.FIREWALL,
              dedup_key=f"fake:{i}", src_ip="203.0.113.5")
        for i in range(n)
    ]
    return CollectionResult(source="fake", events=events, window=window,
                            requested_window=window, reported_total=n, pages=1)


def test_healthy_collection_is_ok(ctx, window):
    health = classify(FakeSource(), full_result(window), ctx)
    assert health.state == HealthState.OK


def test_zero_records_with_no_probes_is_suspect_never_failed(ctx, window):
    """The core distinction: an empty result is not an outage."""
    result = CollectionResult(source="fake", window=window, requested_window=window)
    health = classify(FakeSource(), result, ctx)
    assert health.state == HealthState.SUSPECT
    assert any("cause not established" in n for n in health.notes)
    # The wording must explicitly deny an outage, not merely avoid claiming one.
    assert any("NOT evidence" in n for n in health.notes)
    assert not any("feed failure" in n for n in health.notes)


def test_zero_records_but_probe_returns_data_is_suspect(ctx, window):
    """If an unfiltered probe finds data, the fault is the request, not the feed."""
    probes = [Probe(name="no-time-filter", request="/x", ok=True, status=200, records=5000)]
    result = CollectionResult(source="fake", window=window, requested_window=window)
    health = classify(FakeSource(probes), result, ctx)
    assert health.state == HealthState.SUSPECT


def test_zero_records_and_all_probes_empty_is_failed(ctx, window):
    probes = [
        Probe(name="no-time-filter", request="/x", ok=True, status=200, records=0),
        Probe(name="control", request="/y", ok=True, status=200, records=0),
    ]
    result = CollectionResult(source="fake", window=window, requested_window=window)
    health = classify(FakeSource(probes), result, ctx)
    assert health.state == HealthState.FAILED
    assert any("genuine feed failure" in n for n in health.notes)


def test_auth_failure_is_config_not_outage(ctx, window):
    probes = [Probe(name="auth", request="/z", ok=False, status=401, records=0)]
    result = CollectionResult(source="fake", window=window, requested_window=window)
    health = classify(FakeSource(probes), result, ctx)
    assert health.state == HealthState.SUSPECT
    assert any("configuration fault" in n for n in health.notes)


def test_duplicated_pages_are_degraded(ctx, window):
    result = full_result(window, 100)
    result.events = result.events + result.events   # same dedup keys twice
    health = classify(FakeSource(), result, ctx)
    assert health.state == HealthState.DEGRADED
    assert any("duplicated" in n for n in health.notes)


def test_truncated_pull_is_degraded(ctx, window):
    from datetime import timedelta
    result = full_result(window, 100)
    result.events = [e for e in result.events if e.ts < window.start + timedelta(hours=2)]
    result.reported_total = 100
    health = classify(FakeSource(), result, ctx)
    assert health.state == HealthState.DEGRADED
    assert any("truncated" in n for n in health.notes)


def test_shortfall_against_reported_total_is_degraded(ctx, window):
    result = full_result(window, 100)
    result.reported_total = 1000
    health = classify(FakeSource(), result, ctx)
    assert health.state == HealthState.DEGRADED
    assert any("incomplete" in n for n in health.notes)


def test_retention_clamp_is_a_known_limit_not_a_shortfall(ctx, window):
    """A source with a declared ceiling has not fallen short of anything."""
    from datetime import timedelta
    clamped = Window(start=window.end - timedelta(hours=12), end=window.end)
    result = full_result(clamped, 100)
    result.requested_window = window     # 24h requested, 12h retained
    health = classify(FakeSource(max_hours=12), result, ctx)
    assert health.state == HealthState.DEGRADED
    assert any("known limit" in n for n in health.notes)
    assert not any("truncated" in n for n in health.notes)
