"""Builds and serves the MCP tool surface over streamable HTTP.

Runs in a background thread alongside the scheduler (see ``cli.cmd_serve``).
It is a daemon thread: when the main process exits (the scheduler loop
stopping on SIGTERM/SIGINT), this server goes down with it rather than
keeping the container alive on its own.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import Field

from ..config import Settings
from ..profile import Profile
from ..store import Store
from .auth import BearerAuthMiddleware, resolve_token
from .tools import ToolContext

log = logging.getLogger(__name__)

ReportFormat = Annotated[Literal["text", "json", "markdown"], Field(
    description="text for reading, json for structured fields, markdown for both.")]

#: Must match models.EventKind; tests/test_mcpserver.py checks that it does.
EventKindFilter = Literal["any", "firewall", "dns", "system", "auth", "ids", "flow",
                          "http", "other"]


def build_app(settings: Settings, profile: Profile, store: Store,
              trigger_run: Callable[..., Any]):
    """Returns the fully wrapped ASGI app (tools registered, auth applied)."""
    mcp = build_server(settings, profile, store, trigger_run)
    token = resolve_token(settings)
    app = mcp.streamable_http_app(host=settings.mcp.host,
                                  streamable_http_path=settings.mcp.path)
    return BearerAuthMiddleware(app, token)


def build_server(settings: Settings, profile: Profile, store: Store,
                 trigger_run: Callable[..., Any]):
    """The MCP server with every tool registered, before transport and auth."""
    from mcp.server.mcpserver import MCPServer

    ctx = ToolContext(settings=settings, profile=profile, store=store,
                      trigger_run=trigger_run)
    mcp = MCPServer(
        name="dawnpatrol",
        version="0.1.0",
        instructions=(
            "Read-mostly access to a DawnPatrol network threat-hunting deployment: "
            "past reports, the event store behind the most recent run, and the "
            "network profile that gives findings their context.\n\n"
            "Start here:\n"
            "1. get_latest_report - read what the last run found.\n"
            "2. get_events - look at raw events from the latest run. No SQL needed.\n"
            "3. query_events - only for counts and grouping. Call "
            "describe_event_schema first: it gives the current run id and the real "
            "column names. Every query on the events table must contain "
            "WHERE run_id = '<the current run id>', copied exactly.\n\n"
            "trigger_analysis is the one tool with a side effect - it runs the same "
            "pipeline a scheduled run would, without sending email, so you can "
            "investigate something on demand instead of waiting for tomorrow's report."
        ),
    )

    @mcp.tool()
    def list_reports(
        limit: Annotated[int, Field(description="How many recent runs to list, 1-100.")] = 10,
    ) -> dict:
        """List recent runs, newest first: run_id, status, finding count, cost, and
        time window. Use a run_id from here with get_report."""
        return ctx.list_reports(limit)

    @mcp.tool()
    def get_latest_report(format: ReportFormat = "text") -> dict:
        """Read the most recent report. Takes no required arguments. Start here."""
        return ctx.get_latest_report(format)

    @mcp.tool()
    def get_report(
        run_id: Annotated[str, Field(
            description="Run id exactly as list_reports shows it, e.g. "
                        "20261011T060002Z-3faf83, or latest for the newest report.")],
        format: ReportFormat = "text",
    ) -> dict:
        """Read one report by its run_id, or pass latest for the newest one. Call
        list_reports first to see the ids of older reports."""
        return ctx.get_report(run_id, format)

    @mcp.tool()
    def get_events(
        kind: Annotated[EventKindFilter, Field(
            description="Only this type of event, or any for all types.")] = "any",
        src_ip: Annotated[str, Field(
            description="Only events from this source IP, e.g. 10.0.0.5. "
                        "Leave empty for any.")] = "",
        dst_ip: Annotated[str, Field(
            description="Only events to this destination IP. Leave empty for any.")] = "",
        client_ip: Annotated[str, Field(
            description="Only DNS lookups made by this client IP. "
                        "Leave empty for any.")] = "",
        domain: Annotated[str, Field(
            description="Only DNS lookups of exactly this domain name. "
                        "Leave empty for any.")] = "",
        action: Annotated[str, Field(
            description="Only events with this action, e.g. drop, accept, "
                        "ssh_failed. Leave empty for any.")] = "",
        dst_port: Annotated[int, Field(
            description="Only events to this destination port. 0 means any.")] = 0,
        limit: Annotated[int, Field(description="How many events to return, 1-200.")] = 20,
    ) -> dict:
        """Get raw events from the latest run, newest first. No SQL needed: every
        filter is optional and must match exactly. With no filters, returns the 20
        most recent events of any kind. Use this instead of query_events whenever
        you just want to look at events."""
        return ctx.get_events(limit, kind=kind, src_ip=src_ip, dst_ip=dst_ip,
                              client_ip=client_ip, domain=domain, action=action,
                              dst_port=dst_port)

    @mcp.tool()
    def describe_event_schema() -> str:
        """Get the current run id, the real column names of every table, and example
        queries. Takes no arguments. Call this before your first query_events."""
        return ctx.describe_event_schema()

    @mcp.tool()
    def query_events(
        sql: Annotated[str, Field(description=(
            "One SQL SELECT statement. If it reads the events table it must contain "
            "WHERE run_id = '<current run id>' - get the id from "
            "describe_event_schema. Example: SELECT kind, COUNT(*) FROM events "
            "WHERE run_id = '20261011T060002Z-3faf83' GROUP BY kind"))],
        limit: Annotated[int, Field(description="Maximum rows to return, 1-1000.")] = 200,
    ) -> dict:
        """Run one read-only SQL SELECT for counting and grouping. To just look at
        events, use get_events instead.

        Rules:
        - Only SELECT. No semicolons, no writes.
        - Any query on the events table must include WHERE run_id = '<current run
          id>', copied exactly from describe_event_schema. Only the latest run's
          events can be queried.
        - The events table's columns include id, ts (the event time), kind (the
          event type), source, src_ip, dst_ip, dst_port, proto, action, domain,
          client_ip, device, program, message, user. There is no event_type,
          created_at, or timestamp column: use kind and ts.
        - metrics, signals, entities, ioc_dns and ioc_flow can be read too.

        If a query is rejected or fails, the response includes the current run id,
        a working example query, and the valid column names."""
        return ctx.query_events(sql, limit)

    @mcp.tool()
    def get_metric_history(
        key: Annotated[str, Field(
            description="Exact metric key, e.g. fw.drops or dns.total. "
                        "The metrics table lists every key.")],
        days: Annotated[int, Field(description="How many days back, 1-365.")] = 30,
    ) -> dict:
        """Daily values of one metric over the last N days."""
        return ctx.get_metric_history(key, days)

    @mcp.tool()
    def get_network_profile() -> str:
        """Read the network documentation: zones, hosts, policy, and known quirks from
        profile.yml - the same context the analysis agent sees. Takes no arguments."""
        return ctx.get_network_profile()

    @mcp.tool()
    def list_source_plugins() -> dict:
        """List telemetry sources and whether each is enabled. The names are the valid
        values for trigger_analysis's sources argument. Takes no arguments."""
        return ctx.list_source_plugins()

    @mcp.tool()
    def get_device_directory(
        ip: Annotated[str, Field(
            description="One device's IP for full detail. Leave empty to list "
                        "every device.")] = "",
    ) -> dict:
        """Every device the enabled sources identified in the most recent run: IP,
        hostname, hardware, OS, status, uptime, location, and which source(s)
        reported it."""
        return ctx.get_device_directory(ip)

    @mcp.tool()
    async def trigger_analysis(
        sources: Annotated[list[str] | None, Field(
            description="Source names from list_source_plugins. Omit to use every "
                        "enabled source.")] = None,
        window_hours: Annotated[int | None, Field(
            description="Hours of history to analyse. Omit for the normal "
                        "window.")] = None,
    ) -> dict:
        """Collect fresh data and run a full analysis now. Does not send email. Costs
        real API spend and takes a few minutes, like a scheduled run. Read the result
        afterwards with get_report and the returned run_id."""
        return await ctx.trigger_analysis(sources, window_hours)

    # A second, separate opt-in from DAWNPATROL_MCP_ENABLED: these are the only
    # tools that write something an external agent submits into the context of
    # every future run, which is a different trust boundary than read-only
    # access or a run the operator could already trigger by hand.
    if settings.mcp.notebook_enabled:

        @mcp.tool()
        def read_notebook(
            limit: Annotated[int, Field(description="Most notes to return, 1-2000.")] = 500,
        ) -> dict:
            """Read every note submitted so far, oldest first. Notes supplement
            profile.yml as context for future analysis; they never replace it."""
            return ctx.read_notebook(limit)

        @mcp.tool()
        def add_notebook_entry(
            text: Annotated[str, Field(description="The note itself, in plain sentences.")],
            author: Annotated[str, Field(
                description="Optional: who or what wrote it.")] = "",
        ) -> dict:
            """Submit a note that will be included alongside profile.yml in every
            future run's context, until it ages out of the most recent N entries
            (see read_notebook's injected_into_future_runs count). Use this for
            context that changes faster than the network profile should - a
            newly installed device, a temporary change in expected behavior, an
            explanation for something the last report flagged."""
            return ctx.add_notebook_entry(text, author)

        @mcp.tool()
        def delete_notebook_entry(
            entry_id: Annotated[int, Field(
                description="The note's id number, as read_notebook shows it.")],
        ) -> dict:
            """Delete a note that is no longer relevant, by id (see read_notebook).
            Permanent - there is no undo. Use this to retract a note that turned
            out to be wrong, or clean up one that no longer applies."""
            return ctx.delete_notebook_entry(entry_id)

    return mcp


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
