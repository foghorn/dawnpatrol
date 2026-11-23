"""The web console, end to end against an in-process MCP server: pages,
starting runs, progress, the notebook, login, and escaping of
attacker-written text."""

from __future__ import annotations

import json
import logging
import os
import time

import pytest

pytest.importorskip("jinja2")
pytest.importorskip("starlette")

from starlette.testclient import TestClient  # noqa: E402

from dawnpatrol.mcpserver.server import build_server  # noqa: E402
from dawnpatrol.models import Entity, EntityType, Event, EventKind, Severity, Signal  # noqa: E402
from dawnpatrol.progress import RunProgress, read_progress  # noqa: E402
from dawnpatrol.web.app import build_app  # noqa: E402
from dawnpatrol.web.gateway import McpGateway  # noqa: E402

RUN = "20261123T060001Z-abc123"
EVIL = '<script>alert("x")</script>'


def _report():
    return {
        "run_id": RUN, "generated_at": "2026-11-23T06:00:01+00:00", "site": "t",
        "window": {"start": "2026-11-22T06:00:00+00:00", "end": "2026-11-23T06:00:00+00:00",
                   "hours": 24.0},
        "status": "YELLOW", "degraded": False, "executive_summary": "One thing to check.",
        "finding_count": 1,
        "findings": [{"id": "F1", "title": f"Scanner {EVIL}", "severity": "MEDIUM",
                      "confidence": "high", "taxonomy": "web.scanner", "zone": "dmz",
                      "what": "It probed.", "why": "Because.", "not": "Not a breach.",
                      "action": "Block it.", "signal_ids": ["web.scanners"], "event_ids": [],
                      "evidence_kinds": ["local_behavior"],
                      "entities": [{"type": "ip", "value": "198.51.100.7", "role": "client"}],
                      "enrichment": [], "adjustments": []}],
        "suppressed": [], "metrics": [{"key": "web.requests", "value": 10, "unit": None,
                                       "section": "web", "prior": 8.0, "delta_pct": 25.0}],
        "sources": [{"source": "ssh_host", "state": "OK", "records": 10, "span_hours": 24.0,
                     "requested_hours": 24.0, "notes": []}],
        "devices": [], "trends": [], "actions": [], "data_quality": [], "detection_gaps": [],
        "rejected_findings": [], "canaries": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 0,
                  "cost_usd": 0.0, "model_calls": 3, "model": "m", "analysis_seconds": 61},
    }


@pytest.fixture
def world(settings, profile, store, window):
    settings.mcp.notebook_enabled = True
    out = settings.output_dir
    day = out / "2026-11-23"
    day.mkdir(parents=True, exist_ok=True)
    body = json.dumps(_report())
    (out / "latest.json").write_text(body, encoding="utf-8")
    (day / f"report-{RUN}.json").write_text(body, encoding="utf-8")
    (day / f"report-{RUN}.txt").write_text(f"PLAIN {EVIL}", encoding="utf-8")
    store.start_run(RUN, 1, window.start, window)
    store.insert_events(RUN, [Event(
        ts=window.end - (window.end - window.start) / 2, source="ssh_host",
        kind=EventKind.HTTP, dedup_key="e1", src_ip="198.51.100.7", dst_ip="203.0.113.20",
        action="404", program="GET", domain="example.org", message=f"GET /x {EVIL}",
        user_agent=EVIL)])
    store.save_signals(RUN, [Signal(
        id="web.scanners", analyzer="http_activity", title=f"3 scanners {EVIL}",
        taxonomy="web.scanner", severity_hint=Severity.MEDIUM, confidence=0.6,
        entities=[Entity(EntityType.IP, "198.51.100.7", "client")],
        evidence={"clients": ["198.51.100.7"], "user_agents": [EVIL], "probes": 12,
                  "detail": {"nested": EVIL}})])
    store.finish_run(RUN, finished_at=window.end, status="YELLOW", finding_count=1)
    store.add_notebook_entry(f"note one {EVIL}", author="tester")
    store.add_notebook_entry("note two")

    started: list[dict] = []

    def start_run(**kwargs):
        if started and started[-1].get("busy"):
            return None, "a run is already in progress; try again shortly"
        started.append(kwargs)
        return "20261123T120000Z-fff000", None

    server = build_server(settings, profile, store, trigger_run=lambda **k: (None, "x"),
                          start_run=start_run)
    return {"server": server, "started": started, "settings": settings, "store": store}


def _client(world, password=""):
    app = build_app(McpGateway(server=world["server"]), password=password)
    return TestClient(app, base_url="http://console.test")


def _csrf(client):
    client.get("/")
    return client.cookies.get("dp_csrf")


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

def test_dashboard_shows_the_latest_report_and_runs(world):
    c = _client(world)
    r = c.get("/")
    assert r.status_code == 200
    assert RUN in r.text and "One thing to check." in r.text
    assert "Start run" not in r.text and 'href="/runs"' in r.text
    assert "Notebook" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_attacker_text_is_escaped_everywhere(world):
    c = _client(world)
    for url in ("/", "/runs", f"/runs/{RUN}", f"/runs/{RUN}/text", f"/runs/{RUN}/findings/F1",
                f"/runs/{RUN}/events?src_ip=198.51.100.7", "/notebook"):
        r = c.get(url)
        assert r.status_code == 200, url
        assert EVIL not in r.text, url
    finding = c.get(f"/runs/{RUN}/findings/F1").text
    assert "&lt;script&gt;" in finding and "probes" in finding


def test_finding_page_links_entities_to_their_events(world):
    c = _client(world)
    page = c.get(f"/runs/{RUN}/findings/F1").text
    assert f"/runs/{RUN}/events?src_ip=198.51.100.7" in page
    events = c.get(f"/runs/{RUN}/events?src_ip=198.51.100.7").text
    assert "203.0.113.20" in events and "1 event(s)" in events


def test_unknown_finding_and_run_are_404(world):
    c = _client(world)
    assert c.get(f"/runs/{RUN}/findings/F9").status_code == 404
    assert c.get("/runs/nope").status_code == 404


# --------------------------------------------------------------------------- #
# Starting runs
# --------------------------------------------------------------------------- #

def test_runs_page_has_the_start_form(world):
    page = _client(world).get("/runs").text
    assert "Start a run" in page and "Start run" in page and "Pipeline" in page
    assert 'name="send_email"' in page and 'name="send_email" checked' not in page
    assert "data-start-form hidden" not in page


def test_start_needs_the_form_token(world):
    c = _client(world)
    _csrf(c)
    assert c.post("/runs/start", data={}, follow_redirects=False).status_code == 403
    assert world["started"] == []


def test_start_refuses_another_sites_origin(world):
    c = _client(world)
    token = _csrf(c)
    r = c.post("/runs/start", data={"csrf": token}, follow_redirects=False,
               headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and world["started"] == []


def test_start_without_email_by_default(world):
    c = _client(world)
    token = _csrf(c)
    r = c.post("/runs/start", data={"csrf": token, "window_hours": "6",
                                     "available": ["a", "b"], "sources": ["a"]},
               follow_redirects=False, headers={"origin": "http://console.test"})
    assert r.status_code == 303 and r.headers["location"] == "/runs"
    (call,) = world["started"]
    assert call["skip_outputs"] == frozenset({"smtp"}) and call["trigger"] == "web"
    assert call["window_hours"] == 6 and call["sources"] == ["a"]


def test_start_with_email_and_all_sources(world):
    c = _client(world)
    token = _csrf(c)
    c.post("/runs/start", data={"csrf": token, "send_email": "on",
                                "available": ["a", "b"], "sources": ["a", "b"]},
           follow_redirects=False)
    (call,) = world["started"]
    assert call["skip_outputs"] == frozenset() and call["sources"] is None


def test_busy_start_says_so(world):
    world["started"].append({"busy": True})
    c = _client(world)
    token = _csrf(c)
    r = c.post("/runs/start", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and "busy=" in r.headers["location"]


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #

def test_progress_is_read_from_the_run_log(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dawnpatrol")
    log = logging.getLogger("dawnpatrol.runner")
    with RunProgress(tmp_path, run_id="r1", trigger="web", send_email=False,
                     redact=lambda s: s.replace("sekrit", "***")) as tracker:
        log.info("stage collect: started")
        log.info("stage collect: done in 1m 05s")
        log.info("stage investigate: started")
        logging.getLogger("dawnpatrol.providers.x").info("model call 3: sent to m, waiting")
        logging.getLogger("dawnpatrol.agent.tools").info("tool 7/40: get_events() -> 5 chars")
        log.info("token sekrit leaked")
        time.sleep(1.3)                   # the throttled lines are flushed shortly after
        mid = read_progress(tmp_path)
        tracker.finish(status="GREEN", findings=2)
    assert mid["state"] == "running" and mid["current_stage"] == "investigate"
    assert mid["stages"]["collect"] == {"state": "done", "seconds": 65.0,
                                        "started_at": mid["stages"]["collect"]["started_at"],
                                        "took": "1m 05s"}
    assert mid["model_calls"] == 3 and mid["tool_calls"] == 7 and mid["tool_budget"] == 40
    done = read_progress(tmp_path)
    assert done["state"] == "finished" and done["result"]["finding_count"] == 2
    assert all("sekrit" not in line["msg"] for line in done["log"])
    assert not logging.getLogger("dawnpatrol").handlers or \
        all(not isinstance(h, RunProgress) for h in logging.getLogger("dawnpatrol").handlers)


def test_a_dead_run_is_reported_interrupted(tmp_path):
    (tmp_path / "run-progress.json").write_text(json.dumps(
        {"state": "running", "pid": 999999999, "started_at": "2026-11-23T06:00:00+00:00"}))
    assert read_progress(tmp_path)["state"] == "interrupted"
    assert read_progress(tmp_path / "nothing")["state"] == "idle"


def test_live_page_and_progress_api(world):
    data_dir = world["settings"].data_dir
    (data_dir / "run-progress.json").write_text(json.dumps({
        "state": "running", "pid": os.getpid(), "run_id": "r9", "trigger": "web",
        "started_at": "2026-11-23T06:00:00+00:00",
        "stages": {"collect": {"state": "active", "seconds": None}},
        "log": [{"ts": "06:00:01", "level": "INFO", "logger": "runner", "msg": EVIL}]}))
    c = _client(world)
    page = c.get("/runs")
    assert page.status_code == 200 and "Run in progress" in page.text and EVIL not in page.text
    assert "data-start-form hidden" in page.text      # no starting while one runs
    assert c.get("/live", follow_redirects=False).headers["location"] == "/runs"
    api = c.get("/api/progress").json()
    assert api["state"] == "running" and api["run_id"] == "r9"
    assert "Run in progress" in c.get("/").text


# --------------------------------------------------------------------------- #
# Notebook
# --------------------------------------------------------------------------- #

def test_notebook_lists_and_deletes(world, store):
    c = _client(world)
    page = c.get("/notebook").text
    assert "note two" in page and "&lt;script&gt;" in page
    first = store.list_notebook_entries()[0]["id"]
    token = c.cookies.get("dp_csrf")
    assert c.post(f"/notebook/{first}/delete", data={}).status_code == 403
    r = c.post(f"/notebook/{first}/delete", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    assert [e["text"] for e in store.list_notebook_entries()] == ["note two"]


def test_notebook_hidden_when_the_server_has_it_off(settings, profile, store):
    settings.mcp.notebook_enabled = False
    server = build_server(settings, profile, store, trigger_run=lambda **k: (None, "x"))
    c = TestClient(build_app(McpGateway(server=server)))
    assert ">Notebook<" not in c.get("/").text
    assert c.get("/notebook").status_code == 404


# --------------------------------------------------------------------------- #
# Password
# --------------------------------------------------------------------------- #

def test_password_protects_everything_but_login(world):
    c = _client(world, password="correct horse battery")
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert c.get("/api/progress").status_code == 401
    assert c.get("/static/app.css").status_code == 200
    login = c.get("/login")
    token = c.cookies.get("dp_csrf")
    assert "Sign in" in login.text
    bad = c.post("/login", data={"csrf": token, "password": "nope"})
    assert bad.status_code == 401
    ok = c.post("/login", data={"csrf": token, "password": "correct horse battery",
                                "next": "//evil.example/"}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    assert c.get("/").status_code == 200


def test_repeated_wrong_passwords_lock_out(world):
    c = _client(world, password="correct horse battery")
    c.get("/login")
    token = c.cookies.get("dp_csrf")
    for _ in range(5):
        c.post("/login", data={"csrf": token, "password": "nope"})
    r = c.post("/login", data={"csrf": token, "password": "correct horse battery"})
    assert r.status_code == 429


def test_without_a_password_login_redirects_home(world):
    c = _client(world)
    assert c.get("/login", follow_redirects=False).headers["location"] == "/"


# --------------------------------------------------------------------------- #
# MCP additions
# --------------------------------------------------------------------------- #

def test_get_finding_and_older_runs_events(world):
    from dawnpatrol.mcpserver.tools import ToolContext
    s = world["settings"]
    ctx = ToolContext(settings=s, profile=None, store=world["store"],
                      trigger_run=lambda **k: None)
    out = ctx.get_finding(RUN, "F1")
    assert out["finding"]["id"] == "F1"
    assert out["signals"][0]["evidence"]["probes"] == 12 and out["missing_signals"] == []
    assert ctx.get_finding(RUN, "F7")["finding_ids"] == ["F1"]
    events = ctx.get_events(run_id=RUN, src_ip="198.51.100.7")
    assert events["row_count"] == 1


def test_start_analysis_without_a_background_runner_is_a_clear_error(settings, profile, store):
    from dawnpatrol.mcpserver.tools import ToolContext
    ctx = ToolContext(settings=settings, profile=profile, store=store,
                      trigger_run=lambda **k: None)
    assert "error" in ctx.start_analysis()
