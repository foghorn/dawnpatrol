# MCP server: the agentic-workflow surface

Every other component in this directory serves one closed loop: collect, reduce, judge,
report, deliver, once a day. That loop produces a good morning briefing and nothing
more - it has no notion of "investigate further," because a scheduled batch job doesn't
take follow-up questions.

`dawnpatrol/mcpserver/` is the answer: an MCP (Model Context Protocol) server, reachable
over streamable HTTP, that lets a *second* AI agent - your own Claude session, an
incident-response bot, a SIEM's enrichment step, anything that speaks MCP - read
everything the pipeline has produced and trigger a fresh, targeted look, on demand. The
daily email tells you something looks strange; this is how an agent goes and actually
looks, without you needing to SSH in, without re-deriving context the harness already
has, and without waiting for tomorrow's scheduled run.

That's the shape of an *agentic security workflow* for a home or small-office network:
a standing analyst that reports on its own schedule, plus a door that lets another
agent - human-directed or autonomous - dig deeper the moment something's worth digging
into.

## Why it's safe to expose

**It is one door onto existing rooms, not a new room.** Every tool below is a thin
wrapper over something the scheduled pipeline already does - the same read-only SQL
validator the in-run investigation agent uses, the same `Runner.run()` a terminal
`dawnpatrol run` would call, the same files the `file` output already writes. Auditing
this surface means auditing whether the wrapping is thin, not auditing a second
implementation of read access.

**Off by default, authenticated always.** `DAWNPATROL_MCP_ENABLED` must be set
explicitly - this is the one thing in the whole design that listens on a network
interface. Every request needs `Authorization: Bearer <token>`, checked with a
constant-time comparison so response timing can't leak the token, in a small ASGI
middleware wrapped *around* the MCP app rather than built into it - a choice that keeps
the auth guarantee independent of how a future MCP SDK version changes its own
authentication internals.

**A shared lock, not a convention.** A triggered analysis and the scheduled cron job
both go through the same lock. Two runs writing to the event store at once isn't a
scenario worth supporting; a trigger that arrives mid-cron gets a clean `"a run is
already in progress"` response.

## The tools

| Tool | Signature | What it does |
|---|---|---|
| `list_reports` | `(limit=10)` | Recent runs: id, status, findings, cost, window. |
| `get_latest_report` | `(format="text")` | The most recently delivered report. `format`: `text` \| `json` \| `markdown`. |
| `get_report` | `(run_id, format="text")` | A specific past report by id (from `list_reports`). |
| `describe_event_schema` | `()` | The event-store schema and example queries. Call this before `query_events`. |
| `query_events` | `(sql, limit=200)` | One read-only `SELECT` over events/metrics/signals/entities. Queries against `events` must filter by `run_id`. |
| `get_metric_history` | `(key, days=30)` | A metric's time series, for trend questions. |
| `get_network_profile` | `()` | The zones/hosts/policy/quirks documentation - the same text the analysis agent sees. |
| `list_source_plugins` | `()` | Which sources are enabled - the valid `sources` values for the next tool. |
| `trigger_analysis` | `(sources=None, window_hours=None)` | Collect fresh data and run a full analysis now, **without emailing the result**. Real API spend, real time (a couple of minutes). |

`trigger_analysis` is the one tool with a side effect, and it's worth being precise
about what "without emailing" means mechanically: it calls
`Runner.run(skip_outputs=frozenset({"smtp"}))`, which drops the `smtp` output from the
delivery list before stage 10 runs at all. File output still happens, so the result is
retrievable afterward through `get_report` - a real report exists, it just never leaves
the box as an email.

## A real example of the guardrails holding up

During development, calling `trigger_analysis(sources=["pihole_dns"])` - deliberately
excluding the firewall source - produced a report with **status RED** and an executive
summary calling out the missing firewall telemetry as a monitoring gap, because the
`persistent_prober` canary came back `NOT DETECTED` (there was no firewall analyzer
running to detect it). That's not a bug in the ad hoc trigger path; it's the canary
system (`docs/components/canaries.md`) doing exactly its job even under a partial,
externally-triggered run - which is the kind of thing you want verified with a real
call, not just asserted in a design doc.

## Deployment

```bash
DAWNPATROL_MCP_ENABLED=true
DAWNPATROL_MCP_HOST=0.0.0.0        # bind inside the container
DAWNPATROL_MCP_PORT=5030
DAWNPATROL_MCP_PATH=/mcp
DAWNPATROL_MCP_TOKEN=              # set it, or leave blank and read the startup log once
```

Publish the port bound to a specific host address you control - not a public one -
and treat the token exactly like any other credential in `.env`. If left unset, a
token is generated fresh at process start and logged exactly once:

```
DAWNPATROL_MCP_TOKEN is not set; generated a bearer token for this process only,
shown once: <token> -- set DAWNPATROL_MCP_TOKEN to keep a stable token across restarts.
```

Point any MCP client at `http://<host>:<port><path>` with that bearer token. The
official `mcp` Python SDK's `streamable_http_client` (used in this project's own
integration tests) or Claude Code's own MCP connector both work unmodified against it.

## Build your own tool

Every tool is a thin function registered in `mcpserver/server.py`'s `build_app()`,
backed by a method on `mcpserver.tools.ToolContext`:

```python
# tools.py
def list_suppressions(self) -> dict:
    return {"suppressions": self.store.active_suppressions()}

# server.py, inside build_app()
@mcp.tool()
def list_suppressions() -> dict:
    """List active suppressions - tuned-out false positives, with their expiry."""
    return ctx.list_suppressions()
```

The pattern to keep: **the tool method should be a thin wrapper over something that
already exists** - a `Store` method, a `Runner` call, a validated query - not new logic
written for MCP specifically. If what you want to expose doesn't have a non-MCP
equivalent yet (a CLI command, an internal method), build that first; the MCP tool
should be the second interface onto it, not the first.

### Wire it up and test it

```bash
DAWNPATROL_MCP_ENABLED=true dawnpatrol serve
```

`tests/test_mcpserver.py` is fully offline: tool logic is called directly against a
real temp-directory `Store` (no HTTP), and the bearer-auth middleware is exercised
against a raw ASGI scope (no real socket). For a genuine end-to-end check against the
real wire protocol, use the `mcp` client SDK directly:

```python
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

auth_client = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"})
async with streamable_http_client(url, http_client=auth_client) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool("list_reports", {"limit": 3})
```

That's the exact pattern used to validate this server against a real production
deployment before it was trusted with a real network.
