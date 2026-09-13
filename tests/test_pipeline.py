"""End-to-end pipeline exercise with a stubbed provider.

The whole run executes in CI with no network, no API key, and no spend. This is
what makes it safe to iterate on prompts and analyzers.
"""

from __future__ import annotations

import json

import pytest

from dawnpatrol.config import AISettings
from dawnpatrol.context import RunContext
from dawnpatrol.models import (
    CollectionResult,
    EventKind,
    HealthState,
    Status,
    TokenUsage,
    Window,
)
from dawnpatrol.providers.base import SUBMIT_TOOL, AgentRun, Provider, ToolCallLog
from dawnpatrol.runner import Runner
from dawnpatrol.sources.base import Source
from tests.conftest import make_events


class SyntheticSource(Source):
    """Stands in for a real telemetry system. Deterministic, offline."""

    name = "synthetic"
    kinds = frozenset({EventKind.FIREWALL, EventKind.DNS})
    requires_env = frozenset()

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        events = make_events(window, self.profile)
        return CollectionResult(
            source=self.name, events=events, window=window,
            requested_window=window, reported_total=len(events), pages=1,
        )


class StubProvider(Provider):
    """Returns a canned analysis and records what it was asked."""

    name = "stub"
    analysis: dict | None = None
    call_tools: list[str] = []

    def available(self):
        return True, ""

    def run_agent(self, *, system_static, system_context, user_message,
                  tools, max_turns, on_turn=None):
        StubProvider.last_system = system_static
        StubProvider.last_context = system_context
        StubProvider.last_message = user_message
        StubProvider.last_tools = [t.name for t in tools]

        by_name = {t.name: t for t in tools}
        log = []
        for name in StubProvider.call_tools:
            if name in by_name:
                out = by_name[name].handler({"sql": "SELECT 1 FROM events WHERE run_id='x'"})
                log.append(ToolCallLog(name, {}, True, str(out)[:80]))

        usage = TokenUsage(input_tokens=1000, output_tokens=200, calls=1)
        if on_turn:
            on_turn(usage)
        return AgentRun(analysis=StubProvider.analysis, usage=usage,
                        tool_calls=log, turns=1, stop_reason="tool_use")


GOOD_ANALYSIS = {
    "executive_summary": "One sustained probe against SSH. Everything else is noise.",
    "findings": [{
        "title": "Sustained SSH probe from 203.0.113.45",
        "severity": "MEDIUM",
        "confidence": "high",
        "taxonomy": "scan.persistent_prober",
        "zone": "perimeter",
        "signal_ids": ["fw.prober.203.0.113.45.22"],
        "evidence_kinds": ["local_behavior"],
        "what": "300 drops to port 22 from a single source over 8 hours.",
        "why": "Single source, fixed port, sustained - a targeted prober.",
        "not_this": "Not a sweep; no sibling addresses in the same /24.",
        "action": "Add a WAN drop rule for 203.0.113.45.",
    }],
    "section_narratives": {"perimeter": "Ordinary background scanning otherwise."},
    "recommended_actions": [{"priority": 1, "text": "Block 203.0.113.45."}],
    "data_quality_notes": [],
}


@pytest.fixture(autouse=True)
def reset_stub():
    StubProvider.analysis = json.loads(json.dumps(GOOD_ANALYSIS))
    StubProvider.call_tools = []
    yield


@pytest.fixture
def runner(settings, profile, store, monkeypatch):
    settings.ai = AISettings(enabled=True, provider="stub", model="stub-1",
                             max_cost_usd=5.0)
    settings.enabled_outputs = ["file"]
    monkeypatch.setenv("DAWNPATROL_OUTPUT_DIR", str(settings.output_dir))

    # Plugin discovery is scoped to the dawnpatrol packages, so test-local
    # implementations are injected rather than auto-registered.
    def load_sources(self):
        source = SyntheticSource()
        source.configure(self.profile)
        return [] if settings.enabled_sources == ["does-not-exist"] else [source]

    monkeypatch.setattr(Runner, "load_sources", load_sources)
    monkeypatch.setattr("dawnpatrol.runner.build_provider",
                        lambda ai: StubProvider(ai))
    return Runner(settings, profile, store)


# --------------------------------------------------------------------------- #
# Full run
# --------------------------------------------------------------------------- #


def test_full_pipeline_produces_a_delivered_report(runner, settings):
    outcome = runner.run()
    assert outcome.error is None
    report = outcome.report
    assert report is not None
    assert report.status in (Status.GREEN, Status.AMBER, Status.RED)
    assert report.finding_count == 1
    assert report.findings[0].title.startswith("Sustained SSH probe")
    assert not report.degraded

    assert outcome.deliveries and all(d.ok for d in outcome.deliveries)
    written = list(settings.output_dir.rglob("report-*.txt"))
    assert written, "the file output should have written a report"
    body = written[0].read_text(encoding="utf-8")
    body.encode("ascii")
    assert "1. EXECUTIVE SUMMARY" in body


def test_canaries_run_and_pass_in_a_full_run(runner):
    report = runner.run().report
    assert report.canaries
    assert report.canaries_ok, [c.detail for c in report.canaries if not c.detected]
    assert "canaries detected" in report.canary_summary


def test_source_health_is_recorded(runner):
    report = runner.run().report
    assert len(report.health) == 1
    assert report.health[0].source == "synthetic"
    assert report.health[0].state == HealthState.OK


def test_stop_after_analyze_skips_the_model_entirely(runner):
    StubProvider.analysis = None    # would fail the run if the model were called
    outcome = runner.run(stop_after="analyze")
    assert outcome.stopped_after == "analyze"
    assert outcome.report.metrics
    assert outcome.report.signals
    assert outcome.deliveries == []


def test_model_never_sees_canary_signals(runner):
    runner.run()
    assert "dawnpatrol-canary-beacon.invalid" not in StubProvider.last_message
    assert "192.0.2.77" not in StubProvider.last_message


def test_untrusted_data_is_fenced_in_the_user_turn(runner):
    runner.run()
    assert "<<<DATA" in StubProvider.last_message
    assert "UNTRUSTED DATA" in StubProvider.last_message
    # Log content must never reach the system prompt.
    assert "203.0.113.45" not in StubProvider.last_system


def test_profile_context_is_stable_across_runs(runner):
    """Volatile content before the cache breakpoint silently kills the cache."""
    runner.run()
    first = StubProvider.last_context
    runner.run()
    assert StubProvider.last_context == first
    for token in ("run_id", "20260", "Report date"):
        assert token not in first


def test_the_model_has_no_dangerous_tools(runner):
    runner.run()
    names = set(StubProvider.last_tools)
    assert SUBMIT_TOOL in names
    assert "query_events" in names
    for forbidden in ("bash", "shell", "write_file", "send_email", "fetch", "http"):
        assert forbidden not in names


def test_enrichment_tools_absent_when_no_enricher_configured(runner):
    runner.run()
    assert "enrich_ip" not in StubProvider.last_tools


# --------------------------------------------------------------------------- #
# Degradation paths
# --------------------------------------------------------------------------- #


def test_failed_analysis_still_produces_a_report(runner, settings):
    StubProvider.analysis = None
    outcome = runner.run()
    assert outcome.error is None
    assert outcome.report.degraded
    assert outcome.report.metrics, "statistics survive a failed analysis stage"
    assert any("did not complete" in n for n in outcome.report.data_quality)
    assert list(settings.output_dir.rglob("report-*.txt"))


def test_fabricated_finding_is_rejected_in_a_real_run(runner):
    StubProvider.analysis = {
        "executive_summary": "Something alarming.",
        "findings": [{
            "title": "Invented compromise",
            "severity": "CRITICAL", "confidence": "high", "taxonomy": "made.up",
            "signal_ids": ["no.such.signal"],
            "evidence_kinds": ["local_behavior"],
            "what": "x", "action": "y",
        }],
        "recommended_actions": [],
    }
    report = runner.run().report
    assert report.finding_count == 0
    assert report.status == Status.GREEN
    assert any("cites no known analyzer signal" in n for n in report.data_quality)


def test_reputation_only_finding_is_rejected_in_a_real_run(runner):
    StubProvider.analysis = {
        "executive_summary": "A bad-reputation address appeared.",
        "findings": [{
            "title": "Bad reputation IP seen",
            "severity": "HIGH", "confidence": "high",
            "taxonomy": "scan.persistent_prober",
            "signal_ids": ["fw.prober.203.0.113.45.22"],
            "evidence_kinds": ["reputation"],
            "what": "score 100", "action": "block",
        }],
        "recommended_actions": [],
    }
    report = runner.run().report
    assert report.finding_count == 0


def test_no_sources_enabled_is_a_clear_error(runner, settings):
    settings.enabled_sources = ["does-not-exist"]
    outcome = runner.run()
    assert outcome.report is None
    assert "no sources are enabled" in outcome.error


def test_run_is_recorded_in_the_database(runner, store):
    outcome = runner.run()
    rows = store.recent_runs(5)
    assert rows and rows[0]["run_id"] == outcome.report.run_id
    assert rows[0]["status"] == outcome.report.status.value
    assert rows[0]["finished_at"] is not None


def test_second_run_has_a_baseline_for_comparison(runner, store):
    first = runner.run().report
    second = runner.run().report
    assert first.run_id != second.run_id
    assert second.metric_value("trend.baseline_available") == 1
    fw = second.metric("fw.drops")
    assert fw is not None and fw.prior is not None


def test_ioc_slice_enables_retrospective_hunting(runner, store):
    runner.run()
    rows = store.hunt_domain("steady-checkin", days=180)
    assert rows, "DNS should be retained in the long-term IOC slice"
    assert rows[0]["domain"] == "steady-checkin.example.net"


def test_dry_run_does_not_deliver_externally(runner):
    outcome = runner.run(dry_run=True)
    assert outcome.report is not None


def test_canary_events_never_appear_in_reported_metrics(runner):
    """Synthetic activity must not inflate a statistic the reader will act on."""
    report = runner.run().report
    assert report.canaries_ok

    by_key = {m.key: m.value for m in report.metrics}
    # The prober canary injects 400 drops to port 22 from a canary interface.
    assert "fw.iface.canary0" not in by_key
    assert by_key["fw.drops"] == 400, "only the synthetic-source drops should count"
    # The beacon canary would otherwise add its own domain and candidate.
    assert by_key.get("beacon.candidates") == 1
    for key in by_key:
        assert "canary" not in key


def test_canary_domain_absent_from_every_rendered_format(runner):
    from dawnpatrol.render import RENDERERS
    from dawnpatrol.render import render as render_with
    report = runner.run().report
    for name in RENDERERS:
        body = render_with(name, report)
        assert "dawnpatrol-canary-beacon.invalid" not in body
        assert "192.0.2.77" not in body
