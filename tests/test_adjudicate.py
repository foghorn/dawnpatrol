"""Guardrail enforcement.

Each test feeds the adjudicator a deliberately non-compliant analysis and
asserts the clamp or rejection. These are the rules the original system prompt
stated as instructions; here they are mechanical.
"""

from __future__ import annotations

import pytest

from dawnpatrol.adjudicate import (
    Adjudicator,
    parse_actions,
    parse_trends,
    parse_watchlist,
)
from dawnpatrol.models import Entity, EntityType, Severity, Signal, Status


def signal(sid="s1", hint=Severity.MEDIUM, taxonomy="scan.persistent_prober",
           entity="203.0.113.45") -> Signal:
    return Signal(
        id=sid, analyzer="test", title="test signal", taxonomy=taxonomy,
        severity_hint=hint,
        entities=[Entity(type=EntityType.IP, value=entity, role="source")],
    )


def raw(**kw):
    base = {
        "title": "Sustained SSH probe",
        "severity": "MEDIUM",
        "confidence": "high",
        "taxonomy": "scan.persistent_prober",
        "signal_ids": ["s1"],
        "evidence_kinds": ["local_behavior"],
        "what": "4,812 drops to port 22 from one source.",
        "action": "Add a drop rule.",
    }
    base.update(kw)
    return base


@pytest.fixture
def adj(profile):
    return Adjudicator(profile, [signal()])


# --------------------------------------------------------------------------- #
# Traceability
# --------------------------------------------------------------------------- #


def test_finding_citing_no_signal_is_rejected(adj):
    out = adj.build_findings([raw(signal_ids=[])])
    assert out == []
    assert any("cites no known analyzer signal" in r for r in adj.rejections)


def test_finding_citing_a_fabricated_signal_is_rejected(adj):
    out = adj.build_findings([raw(signal_ids=["does.not.exist"])])
    assert out == []
    assert adj.rejections


def test_unknown_signal_ids_are_dropped_but_valid_ones_kept(adj):
    out = adj.build_findings([raw(signal_ids=["s1", "ghost"])])
    assert len(out) == 1
    assert out[0].signal_ids == ["s1"]
    assert any("ghost" in a for a in out[0].adjustments)


def test_valid_finding_survives_intact(adj):
    out = adj.build_findings([raw()])
    assert len(out) == 1
    assert out[0].severity == Severity.MEDIUM
    assert out[0].id == "F1"


# --------------------------------------------------------------------------- #
# Reputation rules
# --------------------------------------------------------------------------- #


def test_reputation_alone_cannot_create_a_finding(adj):
    out = adj.build_findings([raw(evidence_kinds=["reputation"])])
    assert out == []
    assert any("reputation" in r.lower() for r in adj.rejections)


def test_reputation_with_local_behaviour_is_accepted(adj):
    out = adj.build_findings([raw(evidence_kinds=["local_behavior", "reputation"])])
    assert len(out) == 1


def test_severity_cannot_exceed_signal_hint_by_more_than_one_level(adj):
    out = adj.build_findings([raw(severity="CRITICAL")])  # hint is MEDIUM
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH
    assert any("clamped" in a for a in out[0].adjustments)


def test_one_level_above_the_hint_is_allowed(adj):
    out = adj.build_findings([raw(severity="HIGH")])
    assert out[0].severity == Severity.HIGH
    assert not any("clamped" in a for a in out[0].adjustments)


def test_lowering_severity_below_the_hint_is_always_allowed(adj):
    out = adj.build_findings([raw(severity="INFO")])
    assert out[0].severity == Severity.INFO


def test_critical_from_reputation_is_downgraded(profile):
    a = Adjudicator(profile, [signal(hint=Severity.CRITICAL)])
    out = a.build_findings([raw(severity="CRITICAL",
                                evidence_kinds=["reputation", "baseline_delta"])])
    assert out[0].severity == Severity.HIGH
    assert any("CRITICAL -> HIGH" in x for x in out[0].adjustments)


def test_critical_from_local_evidence_is_preserved(profile):
    a = Adjudicator(profile, [signal(hint=Severity.CRITICAL)])
    out = a.build_findings([raw(severity="CRITICAL", evidence_kinds=["local_behavior"])])
    assert out[0].severity == Severity.CRITICAL


def test_geography_in_justification_is_noted_not_acted_on(adj):
    out = adj.build_findings([raw(severity="HIGH",
                                  why="The source is in Russia, which is suspicious.")])
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH   # unchanged: country is not an input
    assert any("geography" in a.lower() for a in out[0].adjustments)


# --------------------------------------------------------------------------- #
# Attribution
# --------------------------------------------------------------------------- #


def test_nat_gateway_finding_gains_an_attribution_caveat(profile):
    a = Adjudicator(profile, [signal(entity="10.10.0.8")])
    out = a.build_findings([raw(entities=[{"type": "ip", "value": "10.10.0.8"}])])
    assert "NATed" in out[0].attribution_caveat
    assert "iot" in out[0].attribution_caveat


def test_ordinary_host_gets_no_caveat(adj):
    out = adj.build_findings([raw()])
    assert out[0].attribution_caveat == ""


# --------------------------------------------------------------------------- #
# Status rollup
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("severities,expected", [
    ([], Status.GREEN),
    ([Severity.INFO, Severity.LOW], Status.GREEN),
    ([Severity.MEDIUM], Status.GREEN),
    ([Severity.MEDIUM] * 3, Status.AMBER),
    ([Severity.HIGH], Status.AMBER),
    ([Severity.HIGH] * 2, Status.RED),
    ([Severity.CRITICAL], Status.RED),
])
def test_status_rollup(profile, severities, expected):
    a = Adjudicator(profile, [signal(hint=Severity.CRITICAL)])
    findings = a.build_findings([
        raw(title=f"f{i}", severity=s.label(), evidence_kinds=["local_behavior"])
        for i, s in enumerate(severities)
    ])
    assert Adjudicator.rollup(findings) == expected


def test_failed_canary_forces_red_regardless_of_findings(profile):
    assert Adjudicator.rollup([], canaries_ok=False) == Status.RED


# --------------------------------------------------------------------------- #
# Suppression
# --------------------------------------------------------------------------- #


def test_suppression_by_taxonomy_moves_not_deletes(adj):
    findings = adj.build_findings([raw()])
    kept, hidden, matched = adj.apply_suppressions(findings, [
        {"id": 1, "matcher": {"taxonomy": "scan.persistent_prober"},
         "reason": "known scanner"},
    ])
    assert kept == []
    assert len(hidden) == 1
    assert hidden[0].suppressed is True
    assert hidden[0].suppressed_reason == "known scanner"
    assert matched == [1]


def test_suppression_by_entity(adj):
    findings = adj.build_findings([raw()])
    kept, hidden, _ = adj.apply_suppressions(findings, [
        {"id": 2, "matcher": {"entity": "203.0.113.45"}, "reason": "my own scanner"},
    ])
    assert len(hidden) == 1


def test_non_matching_suppression_leaves_the_finding_alone(adj):
    findings = adj.build_findings([raw()])
    kept, hidden, _ = adj.apply_suppressions(findings, [
        {"id": 3, "matcher": {"entity": "10.0.0.1"}, "reason": "unrelated"},
    ])
    assert len(kept) == 1 and hidden == []


def test_max_severity_bounded_suppression_does_not_hide_escalation(adj):
    """A suppression scoped to LOW must not silence the same pattern at HIGH."""
    findings = adj.build_findings([raw(severity="HIGH")])
    kept, hidden, _ = adj.apply_suppressions(findings, [
        {"id": 4, "matcher": {"taxonomy": "scan.persistent_prober", "max_severity": "LOW"},
         "reason": "noise"},
    ])
    assert len(kept) == 1 and hidden == []


def test_empty_matcher_never_suppresses_everything(adj):
    findings = adj.build_findings([raw()])
    kept, hidden, _ = adj.apply_suppressions(findings, [
        {"id": 5, "matcher": {}, "reason": "too broad"},
    ])
    assert len(kept) == 1


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #


def test_parsers_discard_malformed_entries():
    assert len(parse_trends([{"kind": "NEW", "text": "ok"},
                             {"kind": "BOGUS", "text": "x"},
                             {"kind": "NEW", "text": ""}])) == 1
    assert len(parse_actions([{"priority": 1, "text": "do"}, {"text": ""}])) == 1
    assert len(parse_watchlist([{"entity_type": "ip", "entity_value": "1.2.3.4",
                                 "reason": "r"}, {"entity_value": ""}])) == 1


def test_watchlist_expiry_is_bounded():
    out = parse_watchlist([{"entity_type": "ip", "entity_value": "1.2.3.4",
                            "reason": "r", "expires_days": 99999}])
    assert out[0].expires_days == 365
