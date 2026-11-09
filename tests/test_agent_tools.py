"""ToolBox and evidence-bundle behaviour for the internal investigation agent."""

from __future__ import annotations

import json

import pytest

from dawnpatrol.agent.bundle import build_bundle
from dawnpatrol.agent.schema import analysis_problems, unwrap_json_strings
from dawnpatrol.agent.tools import ToolBox
from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.devices import DeviceDirectory
from dawnpatrol.enrichment.broker import EnrichmentBroker
from dawnpatrol.providers.base import SubmissionRejected
from dawnpatrol.query import EventQuery


def _toolbox(store, profile, devices=None, run_id="r1", **kwargs):
    query = EventQuery(store, run_id)
    baseline = Baseline(store, run_id)
    broker = EnrichmentBroker([], store, profile, enabled=False)
    return ToolBox(store=store, query=query, profile=profile, baseline=baseline,
                    broker=broker, signals=[], run_id=run_id, devices=devices, **kwargs)


# --------------------------------------------------------------------------- #
# ToolBox.get_device_directory
# --------------------------------------------------------------------------- #


def test_get_device_directory_lists_all_when_no_ip_given(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", role="librenms-managed",
                  hostname="edge")
    toolbox = _toolbox(store, profile, devices=devices)
    payload = json.loads(toolbox.get_device_directory({}))
    assert payload["devices"][0]["ip"] == "10.10.0.1"
    assert payload["devices"][0]["hostname"] == "edge"


def test_get_device_directory_detail_for_one_ip(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", hostname="edge",
                  hardware="ExampleCo AX-1000")
    toolbox = _toolbox(store, profile, devices=devices)
    payload = json.loads(toolbox.get_device_directory({"ip": "10.10.0.1"}))
    assert payload["hostname"] == "edge"
    assert payload["hardware"] == "ExampleCo AX-1000"


def test_get_device_directory_unknown_ip_is_a_clear_error(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog")
    toolbox = _toolbox(store, profile, devices=devices)
    result = toolbox.get_device_directory({"ip": "10.10.0.99"})
    assert "no directory entry" in result
    assert "10.10.0.1" in result


def test_tool_not_registered_when_no_devices_known(store, profile):
    toolbox = _toolbox(store, profile, devices=DeviceDirectory())
    names = {t.name for t in toolbox.specs()}
    assert "get_device_directory" not in names


def test_tool_registered_when_devices_known(store, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog")
    toolbox = _toolbox(store, profile, devices=devices)
    names = {t.name for t in toolbox.specs()}
    assert "get_device_directory" in names


# --------------------------------------------------------------------------- #
# ToolBox.add_notebook_entry
# --------------------------------------------------------------------------- #


def test_notebook_tool_not_registered_when_disabled(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=False)
    assert "add_notebook_entry" not in {t.name for t in toolbox.specs()}


def test_notebook_tool_registered_when_enabled(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=True)
    assert "add_notebook_entry" in {t.name for t in toolbox.specs()}


def test_add_notebook_entry_stores_and_reports_totals(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=True, notebook_max_injected=50)
    payload = json.loads(toolbox.add_notebook_entry({"text": "gw-office only logs DROP"}))
    assert payload["stored"] is True
    assert payload["total_entries"] == 1
    assert payload["injected_into_future_runs"] == 1
    assert "note" not in payload
    entries = store.list_notebook_entries()
    assert entries[0]["text"] == "gw-office only logs DROP"
    assert entries[0]["author"] == "analysis-agent"


def test_add_notebook_entry_warns_when_it_pushes_an_older_note_out(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=True, notebook_max_injected=2)
    store.add_notebook_entry("note one")
    store.add_notebook_entry("note two")
    payload = json.loads(toolbox.add_notebook_entry({"text": "note three"}))
    assert payload["total_entries"] == 3
    assert payload["injected_into_future_runs"] == 2
    assert "note" in payload and "1" in payload["note"]


def test_add_notebook_entry_rejects_empty_text(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=True)
    assert "required" in toolbox.add_notebook_entry({"text": "  "})


def test_add_notebook_entry_enforces_char_limit(store, profile):
    toolbox = _toolbox(store, profile, notebook_enabled=True, notebook_max_entry_chars=10)
    result = toolbox.add_notebook_entry({"text": "x" * 11})
    assert "over the 10-character limit" in result
    assert store.count_notebook_entries() == 0


# --------------------------------------------------------------------------- #
# build_bundle's DEVICE DIRECTORY section
# --------------------------------------------------------------------------- #


def test_bundle_includes_device_directory_section(window, profile):
    devices = DeviceDirectory()
    devices.update("10.10.0.1", source="librenms_syslog", role="librenms-managed",
                  hostname="edge", hardware="ExampleCo AX-1000")
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1", devices=devices,
    )
    assert "DEVICE DIRECTORY" in bundle
    assert "10.10.0.1" in bundle
    assert "edge" in bundle


def test_bundle_omits_device_directory_section_when_empty(window, profile):
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1", devices=DeviceDirectory(),
    )
    assert "DEVICE DIRECTORY" not in bundle


def test_bundle_works_without_devices_argument_at_all(window, profile):
    """devices is optional - callers that predate this feature still work."""
    bundle = build_bundle(
        window=window, profile=profile, health=[], metrics=[], signals=[],
        notes=[], watchlist=[], enrichment_budgets={}, baseline_available=False,
        run_id="r1",
    )
    assert "DEVICE DIRECTORY" not in bundle


# --------------------------------------------------------------------------- #
# ToolBox.check_submission
# --------------------------------------------------------------------------- #

VALID_ANALYSIS = {
    "executive_summary": "Quiet night.",
    "findings": [],
    "recommended_actions": [{"priority": 1, "text": "Nothing to do."}],
}
STRING_ACTIONS = {**VALID_ANALYSIS, "recommended_actions": ["Block 203.0.113.45"]}


def test_an_analysis_matching_the_schema_is_accepted(store, profile):
    assert _toolbox(store, profile).check_submission(VALID_ANALYSIS) is None


def test_schema_problems_name_the_field_and_what_was_wrong():
    assert analysis_problems(STRING_ACTIONS) == [
        "recommended_actions[0]: 'Block 203.0.113.45' is not of type 'object'"]
    assert analysis_problems("text") == ["top level: 'text' is not of type 'object'"]


def test_a_malformed_analysis_gets_three_corrections_spelling_out_the_format(
        store, profile):
    toolbox = _toolbox(store, profile)
    corrections = [toolbox.check_submission(STRING_ACTIONS) for _ in range(3)]
    assert all("'Block 203.0.113.45' is not of type 'object'" in c for c in corrections)
    assert '"additionalProperties"' in corrections[0], "the full schema is included"
    for later in corrections[1:]:
        assert '"additionalProperties"' not in later, "the schema is sent only once"
        assert "earlier correction" in later
        assert len(later) < len(corrections[0]) / 5
    with pytest.raises(SubmissionRejected, match="after 3 correction"):
        toolbox.check_submission(STRING_ACTIONS)


def test_fields_sent_as_json_text_are_parsed_before_the_check(store, profile):
    toolbox = _toolbox(store, profile)
    args = {**VALID_ANALYSIS,
            "findings": "[]",
            "recommended_actions": json.dumps(VALID_ANALYSIS["recommended_actions"])}
    assert toolbox.check_submission(args) is None, "accepted without a correction"
    assert args == VALID_ANALYSIS, "the provider's copy is the parsed one"
    assert toolbox.unwrapped_fields == ["findings", "recommended_actions"]
    assert toolbox.format_corrections == 0


def test_json_text_is_parsed_only_into_the_type_the_schema_wants():
    nested = {"recommended_actions": ['{"priority": 1, "text": "Block it."}'],
              "findings": '{"not": "a list"}', "executive_summary": "[1, 2]",
              "section_narratives": "not json"}
    assert unwrap_json_strings(nested) == ["recommended_actions[0]"]
    assert nested["recommended_actions"] == [{"priority": 1, "text": "Block it."}]
    assert nested["findings"] == '{"not": "a list"}', "wrong type is left for the check"
    assert nested["executive_summary"] == "[1, 2]", "a string field stays a string"
    assert nested["section_narratives"] == "not json"


def test_json_text_missing_only_its_final_closer_is_parsed():
    actions = '[{"priority": 1, "text": "Block it."}'
    data = {"recommended_actions": actions,
            "section_narratives": '{"perimeter": "Quiet."',
            "findings": '[{"title": "x"}'}
    assert sorted(unwrap_json_strings(data)) == ["findings", "recommended_actions",
                                                 "section_narratives"]
    assert data["recommended_actions"] == [{"priority": 1, "text": "Block it."}]
    assert data["section_narratives"] == {"perimeter": "Quiet."}
    broken = {"findings": '[{"title": "x"'}
    assert unwrap_json_strings(broken) == [], "only a single missing closer is repaired"


def test_a_model_that_stops_without_submitting_is_reminded_once(store, profile):
    toolbox = _toolbox(store, profile)
    submit = next(s for s in toolbox.specs() if s.terminal)
    assert "Call submit_analysis now" in submit.on_stop()
    assert submit.on_stop() is None, "a second stop ends this model's attempt"
    assert toolbox.stop_reminders == 1


def test_json_text_with_stray_closers_or_commas_after_it_is_parsed():
    data = {"findings": '[{"title": "x"}]\n]',
            "section_narratives": '{"perimeter": "Quiet."} }',
            "recommended_actions": '[{"priority": 1, "text": "Block it."}],'}
    assert sorted(unwrap_json_strings(data)) == ["findings", "recommended_actions",
                                                 "section_narratives"]
    assert data["recommended_actions"] == [{"priority": 1, "text": "Block it."}]
    assert data["findings"] == [{"title": "x"}]
    assert data["section_narratives"] == {"perimeter": "Quiet."}
    trailing_text = {"findings": '[{"title": "x"}] and more'}
    assert unwrap_json_strings(trailing_text) == [], "only closers may trail the value"


def test_each_tool_result_shows_the_budget_left(store, profile):
    toolbox = _toolbox(store, profile)
    toolbox.max_calls = 5
    describe = next(s for s in toolbox.specs() if s.name == "describe_schema").handler
    results = [describe({}) for _ in range(6)]
    assert results[0].endswith("\n\n[tool calls used: 1 of 5]")
    assert results[1].endswith("[tool calls used: 2 of 5] 3 remaining - spend them on "
                               "your most important open question, then submit.")
    assert results[4].endswith("[tool calls used: 5 of 5] That was your last tool "
                               "call. Submit your analysis now.")
    assert results[5].startswith("Tool-call budget exhausted")
    assert "tool calls used" not in results[5]


def test_json_text_that_still_fails_the_check_gets_the_correction(store, profile):
    toolbox = _toolbox(store, profile)
    args = {**VALID_ANALYSIS, "recommended_actions": '["Block 203.0.113.45"]'}
    for _ in range(3):
        assert "is not of type 'object'" in toolbox.check_submission(args)
    with pytest.raises(SubmissionRejected):
        toolbox.check_submission(dict(args, recommended_actions='["Block it"]'))


def test_a_corrected_analysis_is_accepted_after_the_follow_up(store, profile):
    toolbox = _toolbox(store, profile)
    assert toolbox.check_submission(STRING_ACTIONS) is not None
    assert toolbox.check_submission(VALID_ANALYSIS) is None
