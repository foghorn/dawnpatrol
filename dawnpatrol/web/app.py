"""The web console's Starlette app: pages over MCP tool calls.

Every page reads through :class:`~dawnpatrol.web.gateway.McpGateway`; the app
never opens the database or report files itself. Templates autoescape
everything, and the Content-Security-Policy allows no inline script, because
the data shown is full of attacker-written text (user agents, URLs, DNS
names, API request bodies).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, Undefined, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .gateway import GatewayError, McpGateway
from .security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    LoginThrottle,
    Sessions,
    new_csrf,
    password_ok,
    same_origin,
)

log = logging.getLogger(__name__)

HERE = Path(__file__).parent
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED"]
#: Event filters the events page accepts (get_events' own filters).
EVENT_FILTERS = ("kind", "src_ip", "dst_ip", "client_ip", "domain", "action", "user",
                 "dst_port")
EVENT_COLUMNS = ("ts", "kind", "source", "src_ip", "dst_ip", "dst_port", "action",
                 "domain", "user", "device", "program", "message")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
_OPEN_PATHS = ("/login", "/static/", "/healthz")


def build_app(gateway: McpGateway, *, password: str = "", session_hours: int = 12,
              secure_cookies: bool = False) -> Starlette:
    # Chainable: a field a tool didn't return (an idle progress state has no
    # elapsed time) renders as nothing instead of failing the page.
    env = Environment(loader=FileSystemLoader(HERE / "templates"),
                      autoescape=select_autoescape(["html"]), undefined=ChainableUndefined)
    env.filters.update(when=_when, duration=_duration, sevclass=_sevclass,
                       pretty=_pretty, scalar=_is_scalar)
    env.tests["scalar"] = _is_scalar
    sessions = Sessions(session_hours)
    throttle = LoginThrottle()

    # ----- helpers ------------------------------------------------------------- #

    async def page(request: Request, template: str, status: int = 200,
                   **context: Any) -> HTMLResponse:
        csrf = request.cookies.get(CSRF_COOKIE) or new_csrf()
        try:
            notebook = "read_notebook" in await gateway.tool_names()
        except GatewayError:
            notebook = False
        html = env.get_template(template).render(
            request=request, csrf=csrf, auth=bool(password), notebook=notebook,
            path=request.url.path, **context)
        resp = HTMLResponse(html, status_code=status)
        if request.cookies.get(CSRF_COOKIE) != csrf:
            resp.set_cookie(CSRF_COOKIE, csrf, httponly=True, samesite="strict",
                            secure=secure_cookies)
        return resp

    async def failure(request: Request, exc: Exception) -> HTMLResponse:
        return await page(request, "error.html", status=502, message=str(exc),
                          mcp_url=gateway.url or "(in-process)")

    async def checked_form(request: Request) -> dict[str, Any] | None:
        form = await request.form()
        token = str(form.get("csrf") or "")
        cookie = request.cookies.get(CSRF_COOKIE) or ""
        if not cookie or token != cookie or not same_origin(
                request.headers.get("origin"), request.headers.get("host")):
            return None
        return {"_raw": form, **{k: form.get(k) for k in form}}

    def forbidden() -> Response:
        return Response("Form expired or came from another site. Go back, reload "
                        "the page and try again.", status_code=403,
                        media_type="text/plain")

    # ----- pages --------------------------------------------------------------- #

    async def dashboard(request: Request) -> Response:
        try:
            progress = await gateway.call("get_run_progress")
            runs = (await gateway.call("list_reports", limit=20)).get("runs", [])
            latest = await gateway.call("get_latest_report", format="json")
        except GatewayError as exc:
            return await failure(request, exc)
        report = latest.get("report") if isinstance(latest, dict) else None
        return await page(
            request, "dashboard.html", progress=progress, runs=runs,
            report=report, report_error=(latest or {}).get("error"),
            counts=_severity_counts(report))

    async def start(request: Request) -> Response:
        form = await checked_form(request)
        if form is None:
            return forbidden()
        raw = form["_raw"]
        chosen = [str(s) for s in raw.getlist("sources")]
        available = [str(s) for s in raw.getlist("available")]
        sources = chosen if chosen and set(chosen) != set(available) else None
        try:
            hours = int(str(form.get("window_hours") or "0"))
        except ValueError:
            hours = 0
        try:
            result = await gateway.call(
                "start_analysis", sources=sources, window_hours=hours or None,
                send_email=form.get("send_email") == "on", requested_by="web")
        except GatewayError as exc:
            return await failure(request, exc)
        if isinstance(result, dict) and result.get("error"):
            return RedirectResponse("/runs?" + urlencode({"busy": result["error"]}),
                                    status_code=303)
        return RedirectResponse("/runs", status_code=303)

    async def runs_page(request: Request) -> Response:
        """Start a run, and watch the current (or last) one."""
        try:
            progress = await gateway.call("get_run_progress")
            plugins = (await gateway.call("list_source_plugins")).get("sources", [])
        except GatewayError as exc:
            return await failure(request, exc)
        return await page(request, "runs.html", progress=progress,
                          sources=[p["name"] for p in plugins if p.get("state") == "enabled"],
                          busy=request.query_params.get("busy"))

    async def old_live(request: Request) -> Response:
        return RedirectResponse("/runs", status_code=308)

    async def api_progress(request: Request) -> Response:
        try:
            progress = await gateway.call("get_run_progress")
        except GatewayError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(progress, headers={"Cache-Control": "no-store"})

    async def run_report(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        try:
            result = await gateway.call("get_report", run_id=run_id, format="json")
        except GatewayError as exc:
            return await failure(request, exc)
        if not isinstance(result, dict) or result.get("error"):
            return await page(request, "error.html", status=404,
                              message=(result or {}).get("error", "report not found"))
        report = result.get("report")
        if not isinstance(report, dict):
            return await page(request, "text.html", run_id=run_id,
                              body=result.get("body", ""), note=result.get("note"))
        findings = sorted(report.get("findings") or [],
                          key=lambda f: _sev_rank(f.get("severity")))
        sections: dict[str, list] = {}
        for m in report.get("metrics") or []:
            sections.setdefault(m.get("section") or "general", []).append(m)
        return await page(request, "run.html", report=report, findings=findings,
                          sections=sections, counts=_severity_counts(report))

    async def run_text(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        try:
            result = await gateway.call("get_report", run_id=run_id, format="text")
        except GatewayError as exc:
            return await failure(request, exc)
        if not isinstance(result, dict) or result.get("error"):
            return await page(request, "error.html", status=404,
                              message=(result or {}).get("error", "report not found"))
        body = result.get("body") or json.dumps(result.get("report"), indent=2)
        return await page(request, "text.html", run_id=run_id, body=body,
                          note=result.get("note"))

    async def finding(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        fid = request.path_params["finding_id"]
        try:
            result = await gateway.call("get_finding", run_id=run_id, finding_id=fid)
        except GatewayError as exc:
            return await failure(request, exc)
        if not isinstance(result, dict) or result.get("error"):
            return await page(request, "error.html", status=404,
                              message=(result or {}).get("error", "finding not found"))
        f = result["finding"]
        return await page(request, "finding.html", run_id=result.get("run_id") or run_id,
                          finding=f, signals=result.get("signals") or [],
                          missing=result.get("missing_signals") or [],
                          entity_links=[_entity_links(e) for e in f.get("entities") or []])

    async def events(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        filters = {k: request.query_params.get(k, "").strip() for k in EVENT_FILTERS}
        filters = {k: v for k, v in filters.items() if v}
        args: dict[str, Any] = dict(filters)
        if "dst_port" in args:
            try:
                args["dst_port"] = int(args["dst_port"])
            except ValueError:
                args.pop("dst_port")
        try:
            result = await gateway.call("get_events", run_id=run_id, limit=200, **args)
        except GatewayError as exc:
            return await failure(request, exc)
        rows = (result or {}).get("events") or [] if isinstance(result, dict) else []
        columns = [c for c in EVENT_COLUMNS if any(r.get(c) not in (None, "") for r in rows)]
        return await page(request, "events.html", run_id=run_id, filters=filters,
                          rows=rows, columns=columns,
                          error=result.get("error") if isinstance(result, dict) else None)

    async def notebook(request: Request) -> Response:
        try:
            if "read_notebook" not in await gateway.tool_names():
                return await page(request, "error.html", status=404,
                                  message="The notebook is turned off on the MCP server "
                                          "(DAWNPATROL_MCP_NOTEBOOK_ENABLED).")
            result = await gateway.call("read_notebook", limit=2000)
        except GatewayError as exc:
            return await failure(request, exc)
        entries = list(reversed(result.get("entries") or []))
        return await page(request, "notebook.html", entries=entries,
                          injected=result.get("injected_into_future_runs", 0),
                          deleted=request.query_params.get("deleted"))

    async def notebook_delete(request: Request) -> Response:
        form = await checked_form(request)
        if form is None:
            return forbidden()
        try:
            entry_id = int(request.path_params["entry_id"])
            await gateway.call("delete_notebook_entry", entry_id=entry_id)
        except (ValueError, GatewayError) as exc:
            return await failure(request, exc)
        return RedirectResponse(f"/notebook?deleted={entry_id}", status_code=303)

    # ----- login --------------------------------------------------------------- #

    async def login(request: Request) -> Response:
        if not password:
            return RedirectResponse("/", status_code=303)
        if request.method == "GET":
            return await page(request, "login.html", error=None)
        client = request.client.host if request.client else "?"
        form = await checked_form(request)
        if form is None:
            return forbidden()
        if throttle.locked(client):
            return await page(request, "login.html", status=429,
                              error="Too many failed attempts. Try again in 15 minutes.")
        if not password_ok(str(form.get("password") or ""), password):
            throttle.failed(client)
            log.warning("web console: failed login from %s", client)
            return await page(request, "login.html", status=401, error="Wrong password.")
        throttle.succeeded(client)
        resp = RedirectResponse(_safe_next(str(form.get("next") or "/")), status_code=303)
        resp.set_cookie(SESSION_COOKIE, sessions.issue(), max_age=sessions.ttl,
                        httponly=True, samesite="strict", secure=secure_cookies)
        return resp

    async def logout(request: Request) -> Response:
        if await checked_form(request) is None:
            return forbidden()
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    async def healthz(request: Request) -> Response:
        return Response("ok", media_type="text/plain")

    # ----- middleware ------------------------------------------------------------ #

    class Guard(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Any) -> Response:
            path = request.url.path
            if password and not path.startswith(_OPEN_PATHS) and \
                    not sessions.valid(request.cookies.get(SESSION_COOKIE)):
                if path.startswith("/api/"):
                    resp: Response = JSONResponse({"error": "login required"},
                                                  status_code=401)
                else:
                    resp = RedirectResponse("/login?" + urlencode({"next": path}),
                                            status_code=303)
            else:
                resp = await call_next(request)
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "same-origin"
            resp.headers["X-Frame-Options"] = "DENY"
            return resp

    routes = [
        Route("/", dashboard),
        Route("/runs/start", start, methods=["POST"]),
        Route("/runs", runs_page),
        Route("/live", old_live),
        Route("/api/progress", api_progress),
        Route("/runs/{run_id}", run_report),
        Route("/runs/{run_id}/text", run_text),
        Route("/runs/{run_id}/findings/{finding_id}", finding),
        Route("/runs/{run_id}/events", events),
        Route("/notebook", notebook),
        Route("/notebook/{entry_id}/delete", notebook_delete, methods=["POST"]),
        Route("/login", login, methods=["GET", "POST"]),
        Route("/logout", logout, methods=["POST"]),
        Route("/healthz", healthz),
        Mount("/static", StaticFiles(directory=HERE / "static"), name="static"),
    ]
    return Starlette(routes=routes, middleware=[Middleware(Guard)])


# --------------------------------------------------------------------------- #
# Template helpers
# --------------------------------------------------------------------------- #

def _sev_rank(sev: Any) -> int:
    s = str(sev or "UNRATED").upper()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _sevclass(sev: Any) -> str:
    s = str(sev or "").lower()
    return f"sev-{s}" if s in ("critical", "high", "medium", "low", "info") else "sev-none"


def _severity_counts(report: dict[str, Any] | None) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in (report or {}).get("findings") or []:
        s = str(f.get("severity") or "UNRATED").upper()
        counts[s] = counts.get(s, 0) + 1
    return sorted(counts.items(), key=lambda kv: _sev_rank(kv[0]))


def _when(value: Any) -> str:
    if not value or isinstance(value, Undefined):
        return ""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt.tzinfo else dt.strftime("%Y-%m-%d %H:%M")


def _duration(seconds: Any) -> str:
    if isinstance(seconds, Undefined):
        return ""
    try:
        s = int(round(float(seconds)))
    except (TypeError, ValueError):
        return ""
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    return f"{m}m {sec:02d}s" if m else f"{sec}s"


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, default=str, ensure_ascii=False)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _entity_links(entity: dict[str, Any]) -> dict[str, Any]:
    kind = str(entity.get("type") or "")
    value = str(entity.get("value") or "")
    links: list[tuple[str, str]] = []
    if kind == "ip":
        links = [("from", urlencode({"src_ip": value})), ("to", urlencode({"dst_ip": value})),
                 ("DNS lookups", urlencode({"client_ip": value}))]
    elif kind == "domain":
        links = [("lookups", urlencode({"domain": value}))]
    elif kind in ("user", "device"):
        links = [("events", urlencode({"user": value}))]
    return {"entity": entity, "links": links}


def _safe_next(target: str) -> str:
    """Only same-site paths: never redirect a login to another site."""
    return target if target.startswith("/") and not target.startswith("//") else "/"
