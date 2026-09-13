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


def test_get_report_finds_by_run_id_across_date_folders(toolctx, settings):
    day_dir = settings.output_dir / "2026-01-01"
    day_dir.mkdir()
    (day_dir / "report-abc123.json").write_text('{"finding_count": 2}', encoding="utf-8")

    out = toolctx.get_report("abc123", format="json")
    assert out["report"]["finding_count"] == 2


def test_get_report_unknown_run_id_is_a_clear_error(toolctx):
    out = toolctx.get_report("does-not-exist")
    assert "error" in out
    assert "does-not-exist" in out["error"]


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

    store.insert_events("run-x", [
        Event(ts=window.start, source="synthetic", kind=EventKind.FIREWALL,
              dedup_key="e1", action="drop"),
    ])
    out = toolctx.query_events("SELECT COUNT(*) AS c FROM events WHERE run_id='run-x'")
    assert out["row_count"] == 1
    assert out["rows"][0][0] == 1


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
# Discovery and trigger
# --------------------------------------------------------------------------- #


def test_list_source_plugins_reports_real_plugins(toolctx):
    out = toolctx.list_source_plugins()
    names = {s["name"] for s in out["sources"]}
    assert "librenms_syslog" in names
    assert "pihole_dns" in names


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
