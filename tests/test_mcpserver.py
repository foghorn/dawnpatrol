"""The external-agent MCP surface: tool logic and bearer auth.

Fully offline - no real HTTP server is started. Tool functions are called
directly against a real (SQLite, temp-dir) Store and Profile, the same way the
ASGI layer would call them; the auth middleware is exercised against a raw
ASGI scope, no network socket involved.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from dawnpatrol.config import Settings
from dawnpatrol.mcpserver.auth import BearerAuthMiddleware, resolve_token
from dawnpatrol.mcpserver.tools import ToolContext
from dawnpatrol.models import Report, Status, TokenUsage
from dawnpatrol.profile import Profile
from dawnpatrol.store import Store


@pytest.fixture
def toolctx(settings: Settings, profile: Profile, store: Store) -> ToolContext:
    calls: list[dict] = []

    def trigger_run(**kwargs):
        calls.append(kwargs)
        report = Report(
            run_id="20260101T000000Z-abcdef", generated_at=None, window=None,
            status=Status.GREEN, site_name=profile.site_name,
            executive_summary="Nothing notable.",
            usage=TokenUsage(cost_usd=0.42),
        )
        from dawnpatrol.runner import RunOutcome
        return RunOutcome(report=report), None

    ctx = ToolContext(settings=settings, profile=profile, store=store,
                      trigger_run=trigger_run)
    ctx._calls = calls  # test-only hook to inspect what trigger_run received
    return ctx


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #


def test_list_reports_reflects_the_database(toolctx, store, window):
    store.start_run("run-1", 1, window.start, window)
    store.finish_run("run-1", finished_at=window.end, status="GREEN", finding_count=0)

    out = toolctx.list_reports()
    assert out["runs"][0]["run_id"] == "run-1"
    assert out["runs"][0]["status"] == "GREEN"
    # datetimes must be JSON-serializable, not raw datetime objects
    json.dumps(out)


def test_get_latest_report_missing_file_is_a_clear_error(toolctx):
    out = toolctx.get_latest_report()
    assert "error" in out


def test_get_latest_report_reads_the_written_file(toolctx, settings):
    (settings.output_dir / "latest.txt").write_text("REPORT BODY", encoding="utf-8")
    out = toolctx.get_latest_report(format="text")
    assert out["body"] == "REPORT BODY"


def test_latest_report_in_an_unwritten_format_falls_back_with_a_note(toolctx, settings):
    """A weak model asked for markdown; this deployment only writes text and json."""
    (settings.output_dir / "latest.txt").write_text("REPORT BODY", encoding="utf-8")
    (settings.output_dir / "latest.json").write_text('{"run_id": "r1"}', encoding="utf-8")

    out = toolctx.get_latest_report(format="markdown")

    assert "error" not in out
    assert out["body"] == "REPORT BODY"
    assert out["format"] == "text"
    assert "does not write markdown" in out["note"]
    assert "text, json" in out["note"]


def test_requested_format_is_used_when_it_exists(toolctx, settings):
    (settings.output_dir / "latest.txt").write_text("TEXT", encoding="utf-8")
    (settings.output_dir / "latest.md").write_text("# MD", encoding="utf-8")
    out = toolctx.get_latest_report(format="markdown")
    assert out["body"] == "# MD" and "note" not in out


def test_json_report_carries_its_real_run_id_not_the_file_name(toolctx, settings):
    (settings.output_dir / "latest.json").write_text(
        '{"run_id": "20261020T060001Z-129a55"}', encoding="utf-8")
    out = toolctx.get_latest_report(format="json")
    assert out["run_id"] == "20261020T060001Z-129a55"


def test_past_report_in_an_unwritten_format_falls_back(toolctx, settings):
    day_dir = settings.output_dir / "2026-01-01"
    day_dir.mkdir()
    (day_dir / "report-abc123.txt").write_text("OLD REPORT", encoding="utf-8")
    out = toolctx.get_report("abc123", format="markdown")
    assert out["body"] == "OLD REPORT" and "note" in out


def test_get_report_finds_by_run_id_across_date_folders(toolctx, settings):
    day_dir = settings.output_dir / "2026-01-01"
    day_dir.mkdir()
    (day_dir / "report-abc123.json").write_text('{"finding_count": 2}', encoding="utf-8")

    out = toolctx.get_report("abc123", format="json")
    assert out["report"]["finding_count"] == 2


def test_get_report_unknown_run_id_is_a_clear_error(toolctx, store, window):
    store.start_run("20261011T060002Z-3faf83", 1, window.start, window)
    out = toolctx.get_report("does-not-exist")
    assert "does-not-exist" in out["error"]
    assert out["recent_run_ids"] == ["20261011T060002Z-3faf83"]


@pytest.mark.parametrize("run_id", ["latest", "Latest", " last ", "most recent", ""])
def test_get_report_treats_latest_as_the_newest_report(toolctx, settings, run_id):
    """A weak model asked for run_id='latest' rather than calling get_latest_report."""
    (settings.output_dir / "latest.txt").write_text("NEWEST", encoding="utf-8")
    assert toolctx.get_report(run_id)["body"] == "NEWEST"


# --------------------------------------------------------------------------- #
# Raw and aggregate data
# --------------------------------------------------------------------------- #


def test_describe_event_schema_mentions_the_events_table(toolctx):
    text = toolctx.describe_event_schema()
    assert "events" in text
    assert "run_id" in text


def test_query_events_rejects_a_write_statement(toolctx):
    out = toolctx.query_events("DELETE FROM events")
    assert "error" in out
    assert "rejected" in out["error"]


def test_query_events_runs_a_real_select(toolctx, store, window):
    from dawnpatrol.models import Event, EventKind

    # query_events scopes to the most recently recorded run (store.recent_runs),
    # so that run must actually exist for a run_id-scoped query to validate.
    store.start_run("run-x", 1, window.start, window)
    store.finish_run("run-x", finished_at=window.end, status="GREEN", finding_count=0)
    store.insert_events("run-x", [
        Event(ts=window.start, source="synthetic", kind=EventKind.FIREWALL,
              dedup_key="e1", action="drop"),
    ])
    out = toolctx.query_events("SELECT COUNT(*) AS c FROM events WHERE run_id='run-x'")
    assert out["row_count"] == 1
    assert out["rows"][0][0] == 1


def test_query_events_rejects_scoping_to_a_run_other_than_the_current_one(toolctx, store, window):
    store.start_run("run-x", 1, window.start, window)
    store.finish_run("run-x", finished_at=window.end, status="GREEN", finding_count=0)
    out = toolctx.query_events("SELECT * FROM events WHERE run_id='some-other-run'")
    assert "error" in out
    assert "rejected" in out["error"]


def _finished_run_with_events(store, window, run_id="20261011T060002Z-3faf83"):
    from dawnpatrol.canary import CANARY_SOURCE
    from dawnpatrol.models import Event, EventKind

    store.start_run(run_id, 1, window.start, window)
    store.finish_run(run_id, finished_at=window.end, status="GREEN", finding_count=0)
    store.insert_events(run_id, [
        Event(ts=window.start, source="synthetic", kind=EventKind.FIREWALL,
              dedup_key="fw1", src_ip="203.0.113.9", dst_ip="10.0.0.5",
              dst_port=22, action="drop"),
        Event(ts=window.end, source="synthetic", kind=EventKind.DNS,
              dedup_key="dns1", client_ip="10.0.0.7", domain="example.com"),
        Event(ts=window.end, source=CANARY_SOURCE, kind=EventKind.FIREWALL,
              dedup_key="canary1", src_ip="198.51.100.1", action="drop"),
    ])
    return run_id


def test_unscoped_query_gets_back_the_run_id_and_a_working_example(toolctx, store, window):
    """The exact query a weak model sent: no run_id, and guessed column names."""
    run_id = _finished_run_with_events(store, window)
    out = toolctx.query_events(
        "SELECT event_type, message, created_at FROM events ORDER BY created_at DESC LIMIT 20")

    assert "rejected" in out["error"]
    assert out["current_run_id"] == run_id
    assert "get_events" in out["tip"]
    example = toolctx.query_events(out["example_query"])
    assert "error" not in example, "the suggested fix must itself run"
    assert example["row_count"] == 3


def test_wrong_column_names_get_back_the_real_ones(toolctx, store, window):
    run_id = _finished_run_with_events(store, window)
    out = toolctx.query_events(
        f"SELECT event_type, created_at FROM events WHERE run_id = '{run_id}'")

    assert "failed" in out["error"]
    assert {"kind", "ts", "message"} <= set(out["valid_columns"]["events"])
    assert "event_type" not in out["valid_columns"]["events"]
    assert "example_query" in out


def test_describe_event_schema_leads_with_the_current_run_id(toolctx, store, window):
    run_id = _finished_run_with_events(store, window)
    first_line = toolctx.describe_event_schema().splitlines()[0]
    assert first_line == f"CURRENT RUN ID: {run_id}"


def test_get_events_needs_no_sql_and_skips_canaries(toolctx, store, window):
    run_id = _finished_run_with_events(store, window)
    out = toolctx.get_events()

    assert out["run_id"] == run_id
    assert out["row_count"] == 2
    assert all("id" in e and "raw_json" not in e for e in out["events"])
    assert not any(e.get("src_ip") == "198.51.100.1" for e in out["events"])


def test_get_events_filters_exactly(toolctx, store, window):
    _finished_run_with_events(store, window)
    out = toolctx.get_events(kind="firewall", dst_port=22)
    assert [e["src_ip"] for e in out["events"]] == ["203.0.113.9"]
    assert toolctx.get_events(domain="nope.example")["row_count"] == 0
    # The tool's flat defaults mean "no filter", exactly like omitting them.
    defaults = toolctx.get_events(kind="any", src_ip="", dst_port=0)
    assert defaults["filters"] == {} and defaults["row_count"] == 2


def test_get_events_rejects_an_unknown_filter(toolctx, store, window):
    _finished_run_with_events(store, window)
    out = toolctx.get_events(event_type="dns")
    assert "event_type" in out["error"]
    assert "kind" in out["error"]


def test_get_events_before_any_run_is_a_clear_error(toolctx):
    assert "no run" in toolctx.get_events()["error"]


def test_event_kind_filter_matches_the_model():
    from typing import get_args

    from dawnpatrol.mcpserver.server import EventKindFilter
    from dawnpatrol.models import EventKind

    assert set(get_args(EventKindFilter)) == {k.value for k in EventKind} | {"any"}


def test_every_tool_and_parameter_is_described(settings, profile, store):
    """Weak models lean on these descriptions; none may be left blank."""
    from dawnpatrol.mcpserver.server import build_server

    settings.mcp.notebook_enabled = True
    mcp = build_server(settings, profile, store, trigger_run=lambda **_: (None, None))
    tools = asyncio.run(mcp.list_tools())

    assert {"get_events", "query_events", "add_notebook_entry"} <= {t.name for t in tools}
    for tool in tools:
        assert tool.description, f"{tool.name} has no description"
        for name, prop in tool.input_schema.get("properties", {}).items():
            assert prop.get("description"), f"{tool.name}.{name} has no description"


def test_get_metric_history_empty_is_not_an_error(toolctx):
    out = toolctx.get_metric_history("no.such.metric")
    assert out["series"] == []
    assert "note" in out


# --------------------------------------------------------------------------- #
# Network documentation
# --------------------------------------------------------------------------- #


def test_get_network_profile_contains_configured_zones(toolctx):
    text = toolctx.get_network_profile()
    assert "lan" in text
    assert "iot" in text


# --------------------------------------------------------------------------- #
# Agent notebook
# --------------------------------------------------------------------------- #


def test_add_and_read_notebook_entry(toolctx):
    result = toolctx.add_notebook_entry("New IoT device installed today.", author="ops-agent")
    assert result["stored"] is True

    out = toolctx.read_notebook()
    assert out["count"] == 1
    assert out["entries"][0]["text"] == "New IoT device installed today."
    assert out["entries"][0]["author"] == "ops-agent"


def test_add_notebook_entry_rejects_empty_text(toolctx):
    result = toolctx.add_notebook_entry("   ")
    assert "error" in result
    assert toolctx.read_notebook()["count"] == 0


def test_add_notebook_entry_rejects_over_length_text(toolctx):
    toolctx.settings.mcp.notebook_max_entry_chars = 20
    result = toolctx.add_notebook_entry("x" * 21)
    assert "error" in result
    assert "20-character limit" in result["error"]
    assert toolctx.read_notebook()["count"] == 0


def test_delete_notebook_entry_removes_it(toolctx):
    added = toolctx.add_notebook_entry("no longer relevant")
    result = toolctx.delete_notebook_entry(added["id"])
    assert result == {"id": added["id"], "deleted": True}
    assert toolctx.read_notebook()["count"] == 0


def test_delete_notebook_entry_unknown_id_is_a_clear_error(toolctx):
    result = toolctx.delete_notebook_entry(999999)
    assert "error" in result


def test_read_notebook_reports_how_many_are_injected(toolctx):
    toolctx.settings.mcp.notebook_max_injected = 2
    for i in range(3):
        toolctx.add_notebook_entry(f"note {i}")
    out = toolctx.read_notebook()
    assert out["count"] == 3
    assert out["injected_into_future_runs"] == 2


# --------------------------------------------------------------------------- #
# Discovery and trigger
# --------------------------------------------------------------------------- #


def test_list_source_plugins_reports_real_plugins(toolctx):
    out = toolctx.list_source_plugins()
    names = {s["name"] for s in out["sources"]}
    assert "librenms_syslog" in names
    assert "pihole_dns" in names


def _write_latest_report(settings, devices: list[dict], run_id: str = "run-1") -> None:
    import json as _json

    body = {"run_id": run_id, "devices": devices}
    (settings.output_dir / "latest.json").write_text(_json.dumps(body), encoding="utf-8")


def test_get_device_directory_missing_report_is_a_clear_error(toolctx):
    out = toolctx.get_device_directory()
    assert "error" in out


def test_get_device_directory_lists_devices_from_the_latest_report(toolctx, settings):
    _write_latest_report(settings, [
        {"ip": "10.10.0.1", "hostname": "edge", "hardware": "ASUS RT-AX88U Pro",
         "roles": ["librenms-managed"], "sources": ["librenms_syslog"]},
        {"ip": "10.10.0.55", "hostname": "", "roles": ["dns-client"],
         "sources": ["pihole_dns"]},
    ])

    out = toolctx.get_device_directory()
    assert out["run_id"] == "run-1"
    by_ip = {d["ip"]: d for d in out["devices"]}
    assert by_ip["10.10.0.1"]["hostname"] == "edge"
    assert by_ip["10.10.0.1"]["hardware"] == "ASUS RT-AX88U Pro"
    assert "librenms-managed" in by_ip["10.10.0.1"]["roles"]
    assert "dns-client" in by_ip["10.10.0.55"]["roles"]


def test_get_device_directory_detail_for_one_ip(toolctx, settings):
    _write_latest_report(settings, [{"ip": "10.10.0.1", "hostname": "edge"}])

    out = toolctx.get_device_directory("10.10.0.1")
    assert out["hostname"] == "edge"

    out = toolctx.get_device_directory("10.10.0.99")
    assert "error" in out
    assert "10.10.0.1" in out["error"]


def test_get_device_directory_empty_devices_is_a_clear_error(toolctx, settings):
    _write_latest_report(settings, [])
    out = toolctx.get_device_directory()
    assert "error" in out


def test_trigger_analysis_never_requests_email(toolctx):
    result = asyncio.run(toolctx.trigger_analysis(sources=["pihole_dns"]))
    assert result["status"] == "GREEN"
    assert result["email_sent"] is False
    assert toolctx._calls[0]["sources"] == ["pihole_dns"]
    assert "smtp" in toolctx._calls[0]["skip_outputs"]


def test_trigger_analysis_surfaces_a_busy_run(toolctx):
    def busy_trigger(**kwargs):
        return None, "a run is already in progress; try again shortly"

    toolctx.trigger_run = busy_trigger
    result = asyncio.run(toolctx.trigger_analysis())
    assert "already in progress" in result["error"]


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #


def test_resolve_token_prefers_the_configured_value(settings):
    settings.mcp.token = _secret("configured-token")
    assert resolve_token(settings) == "configured-token"


def test_resolve_token_generates_one_when_unset(settings, caplog):
    settings.mcp.token = _secret("")
    token = resolve_token(settings)
    assert len(token) > 20
    assert any("generated a bearer token" in r.message for r in caplog.records)


def test_bearer_middleware_rejects_missing_token():
    app = _record_calls_app()
    mw = BearerAuthMiddleware(app.asgi, "secret-token")
    status = asyncio.run(_call(mw, headers=[]))
    assert status == 401
    assert not app.called


def test_bearer_middleware_rejects_wrong_token():
    app = _record_calls_app()
    mw = BearerAuthMiddleware(app.asgi, "secret-token")
    status = asyncio.run(_call(mw, headers=[(b"authorization", b"Bearer wrong")]))
    assert status == 401
    assert not app.called


def test_bearer_middleware_accepts_the_right_token():
    app = _record_calls_app()
    mw = BearerAuthMiddleware(app.asgi, "secret-token")
    status = asyncio.run(_call(mw, headers=[(b"authorization", b"Bearer secret-token")]))
    assert status == 200
    assert app.called


# ----- helpers ------------------------------------------------------------- #


def _secret(value: str):
    from dawnpatrol.secrets import SecretStr
    return SecretStr(value)


class _App:
    def __init__(self):
        self.called = False

    async def asgi(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _record_calls_app() -> _App:
    return _App()


async def _call(app, headers: list[tuple[bytes, bytes]]) -> int:
    scope = {"type": "http", "method": "GET", "path": "/mcp", "headers": headers}
    status = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            status["code"] = message["status"]

    await app(scope, receive, send)
    return status["code"]
