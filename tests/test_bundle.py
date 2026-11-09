"""Signal rendering in the evidence bundle: smaller, but nothing lost."""

from __future__ import annotations

import json

from dawnpatrol.agent.bundle import TABLE_MIN_SIGNALS, _signals_block, build_bundle
from dawnpatrol.models import Entity, EntityType, Severity, Signal

PROBER_NOTE = "Single source, fixed destination port - a targeted prober."


def _prober(i: int, severity: Severity = Severity.LOW, note: str = PROBER_NOTE) -> Signal:
    ip = f"203.0.113.{i}"
    return Signal(
        id=f"fw.prober.{ip}.17445", analyzer="firewall",
        title=f"Sustained probe from {ip} against port 17445",
        taxonomy="scan.persistent_prober", severity_hint=severity, confidence=0.6,
        entities=[Entity(EntityType.IP, ip, "source"),
                  Entity(EntityType.PORT, "17445", "destination")],
        evidence={"hits": 100 + i, "ttl_range": [45, 48]},
        narrative_hint=note,
    )


def _beacon(i: int) -> Signal:
    return Signal(
        id=f"beacon.dns.10.0.0.{i}.example.com", analyzer="beacon",
        title=f"Periodic DNS from 10.0.0.{i}", taxonomy="c2.beacon_candidate",
        severity_hint=Severity.MEDIUM, confidence=0.9,
        entities=[Entity(EntityType.IP, f"10.0.0.{i}", "client")],
        evidence={"period_s": 60}, narrative_hint="Regular interval check-in.",
    )


def _json_lines(block: str) -> list[dict]:
    body = block.split("<<<DATA\n", 1)[1].split("\nDATA>>>", 1)[0]
    return [json.loads(line) for line in body.splitlines()]


def test_every_signal_id_still_appears_once():
    signals = [_beacon(i) for i in range(3)] + [_prober(i) for i in range(10)]
    block = _signals_block(signals)
    for s in signals:
        assert block.count(s.id) == 1, s.id


def test_shared_note_printed_once_not_per_signal():
    block = _signals_block([_beacon(i) for i in range(4)])
    assert block.count("Regular interval check-in.") == 1
    assert all("note" not in d for d in _json_lines(block))


def test_distinct_note_kept_on_its_signal():
    odd = _beacon(9)
    odd.narrative_hint = "Something specific about this one."
    block = _signals_block([_beacon(1), _beacon(2), odd])
    by_id = {d["id"]: d for d in _json_lines(block)}
    assert by_id[odd.id]["note"] == "Something specific about this one."
    assert "note" not in by_id[_beacon(1).id]


def test_signals_are_compact_one_line_json():
    block = _signals_block([_beacon(1), _beacon(2)])
    assert '": ' not in block.split("<<<DATA", 1)[1]  # no pretty-print spacing
    assert len(_json_lines(block)) == 2


def test_many_low_signals_of_one_taxonomy_become_a_table():
    signals = [_prober(i) for i in range(TABLE_MIN_SIGNALS)]
    block = _signals_block(signals)
    assert "scan.persistent_prober: 5 LOW/INFO signals as a table" in block
    rows = block.split("<<<DATA\n", 1)[1].split("\nDATA>>>", 1)[0].splitlines()
    assert rows[0].startswith("id | severity_hint | confidence | entities | hits | ttl_range")
    assert rows[1] == ("fw.prober.203.0.113.0.17445 | LOW | 0.6 | "
                       "source=ip:203.0.113.0 destination=port:17445 | 100 | [45,48]")


def test_few_low_signals_stay_as_json():
    block = _signals_block([_prober(i) for i in range(TABLE_MIN_SIGNALS - 1)])
    assert "as a table" not in block
    assert len(_json_lines(block)) == TABLE_MIN_SIGNALS - 1


def test_medium_signal_of_a_tabled_taxonomy_keeps_full_detail():
    loud = _prober(99, severity=Severity.MEDIUM)
    signals = [loud] + [_prober(i) for i in range(TABLE_MIN_SIGNALS)]
    block = _signals_block(signals)
    full_ids = {d["id"] for d in _json_lines(block)}
    assert full_ids == {loud.id}


def test_table_cells_cannot_break_columns():
    signals = [_prober(i) for i in range(TABLE_MIN_SIGNALS)]
    signals[0].evidence["hits"] = "a|b\nc"
    block = _signals_block(signals)
    assert "a\\|b c" in block


def test_no_signals():
    assert "(none)" in _signals_block([])


def test_build_bundle_uses_compact_signals(window, profile):
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[],
        signals=[_beacon(1), _beacon(2)], notes=[],
        watchlist=[{"subject": "1.2.3.4", "reason": "seen"}],
        enrichment_budgets={}, baseline_available=False, run_id="r1",
    )
    assert "ANALYZER SIGNALS (2 shown of 2)" in bundle
    assert '{"subject":"1.2.3.4","reason":"seen"}' in bundle
