"""Builds and serves the MCP tool surface over streamable HTTP.

Runs in a background thread alongside the scheduler (see ``cli.cmd_serve``).
It is a daemon thread: when the main process exits (the scheduler loop
stopping on SIGTERM/SIGINT), this server goes down with it rather than
keeping the container alive on its own.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ..config import Settings
from ..profile import Profile
from ..store import Store
from .auth import BearerAuthMiddleware, resolve_token
from .tools import ToolContext

log = logging.getLogger(__name__)


def build_app(settings: Settings, profile: Profile, store: Store,
              trigger_run: Callable[..., Any]):
    """Returns the fully wrapped ASGI app (tools registered, auth applied)."""
    from mcp.server.mcpserver import MCPServer

    ctx = ToolContext(settings=settings, profile=profile, store=store,
                      trigger_run=trigger_run)
    mcp = MCPServer(
        name="dawnpatrol",
        version="0.1.0",
        instructions=(
            "Read-mostly access to a DawnPatrol network threat-hunting deployment: "
            "past reports, the raw/aggregate event store for the runs that produced "
            "them, and the network profile that gives findings their context. "
            "trigger_analysis is the one tool with a side effect - it runs the same "
            "pipeline a scheduled run would, without sending email, so you can "
            "investigate something on demand instead of waiting for tomorrow's report."
        ),
    )

    @mcp.tool()
    def list_reports(limit: int = 10) -> dict:
        """List recent runs: run_id, status, finding count, cost, and window."""
        return ctx.list_reports(limit)

    @mcp.tool()
    def get_latest_report(format: str = "text") -> dict:
        """Read the most recently delivered report. format: text | json | markdown."""
        return ctx.get_latest_report(format)

    @mcp.tool()
    def get_report(run_id: str, format: str = "text") -> dict:
        """Read a specific past report by run_id (see list_reports). format: text | json | markdown."""
        return ctx.get_report(run_id, format)

    @mcp.tool()
    def describe_event_schema() -> str:
        """Show the event-store schema and example queries. Call before query_events."""
        return ctx.describe_event_schema()

    @mcp.tool()
    def query_events(sql: str, limit: int = 200) -> dict:
        """Run one read-only SELECT over collected events, metrics, signals, and
        entity history. Queries against `events` must filter by run_id (see
        list_reports for ids); metrics/entities/ioc tables are not run-scoped.
        Call describe_event_schema first if unsure of the columns."""
        return ctx.query_events(sql, limit)

    @mcp.tool()
    def get_metric_history(key: str, days: int = 30) -> dict:
        """Time series for one metric key (e.g. 'fw.drops.total') over N days."""
        return ctx.get_metric_history(key, days)

    @mcp.tool()
    def get_network_profile() -> str:
        """Read the configured network documentation: zones, hosts, policy, and
        known quirks from profile.yml - the same context the analysis agent sees."""
        return ctx.get_network_profile()

    @mcp.tool()
    def list_source_plugins() -> dict:
        """List telemetry sources and whether each is enabled - the valid `sources`
        values for trigger_analysis."""
        return ctx.list_source_plugins()

    @mcp.tool()
    async def trigger_analysis(sources: list[str] | None = None,
                                window_hours: int | None = None) -> dict:
        """Collect fresh data and run a full analysis now, without emailing the
        result. Optionally restrict to specific source plugin names (see
        list_source_plugins); omit to use every enabled source. The finished
        report is written to disk as usual and retrievable via get_report. Costs
        real API spend and takes a couple of minutes, same as a scheduled run."""
        return await ctx.trigger_analysis(sources, window_hours)

    token = resolve_token(settings)
    app = mcp.streamable_http_app(host=settings.mcp.host,
                                  streamable_http_path=settings.mcp.path)
    return BearerAuthMiddleware(app, token)


def serve_forever(settings: Settings, profile: Profile, store: Store,
                  trigger_run: Callable[..., Any]) -> None:
    """Blocking call - run this in its own thread."""
    import uvicorn

    app = build_app(settings, profile, store, trigger_run)
    log.info("MCP server listening on http://%s:%d%s (bearer token required)",
             settings.mcp.host, settings.mcp.port, settings.mcp.path)
    config = uvicorn.Config(app, host=settings.mcp.host, port=settings.mcp.port,
                            log_level="warning")
    uvicorn.Server(config).run()
