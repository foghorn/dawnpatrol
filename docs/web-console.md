# Web console

An optional browser view of DawnPatrol:

- **Dashboard:** the latest report's status, findings and source health, any
  run in progress, and recent runs.
- **Run report:** the full report: findings, recommended actions, trends,
  statistics, source health, data quality, detection gaps, the self-test, and
  the plain-text version that gets emailed.
- **Finding:** what happened and why it matters, its entities (each linking to
  that run's matching events), enrichment, the adjudicator's changes, and every
  signal behind it with its evidence.
- **Runs:** the form to start a run, next to the current (or last) run's
  progress: each pipeline stage with its status and duration, model and tool
  call counts, and the run's log, refreshed every two seconds. It also shows
  runs started by the schedule, by MCP, or with `docker exec ... dawnpatrol run`.
  The form is hidden while a run is going and comes back when it ends.
- **Notebook:** every note, newest first, marked when it's within the set the
  next run reads, with a delete button. It only appears when the MCP server has
  the notebook enabled.

## Pages

| URL | Page |
|---|---|
| `/` | Dashboard |
| `/runs` | Runs: start a run, watch the current or last one (`/live` redirects here) |
| `/runs/<run_id>` | A run's report |
| `/runs/<run_id>/text` | The same report as plain text |
| `/runs/<run_id>/findings/<finding_id>` | One finding and its signals |
| `/runs/<run_id>/events?src_ip=…` | That run's events, filtered by `src_ip`, `dst_ip`, `client_ip`, `domain`, `user`, `action`, `kind` or `dst_port` (newest 200) |
| `/notebook` | Notebook (only when the MCP server has it enabled) |
| `/api/progress` | The progress JSON the Runs page polls |
| `/healthz` | `ok`, without login, for uptime checks |

Events exist only for runs still within raw retention
(`DAWNPATROL_RETENTION_RAW_DAYS`); for older runs the report and findings still
show, the events page comes back empty.

## How it works

The console is an **MCP client**. Every page is made of MCP tool calls to
DawnPatrol's own MCP server, with the same bearer token any other client uses.
It never opens the database or report files itself, so it can run anywhere
that can reach the MCP port, and anything it shows, an MCP client can get too.

```
browser ──HTTP──▶ web console (WEB_PORT) ──MCP + bearer token──▶ MCP server (MCP_PORT)
```

Three MCP tools exist mainly for it, and work for any client:

| Tool | Does |
|---|---|
| `start_analysis(sources, window_hours, send_email)` | Starts a run in the background and returns its `run_id` at once. Only one run happens at a time. Email is off unless asked for. |
| `get_run_progress()` | The current or last run: state, each stage's status and duration, model and tool call counts, the last 150 log lines. |
| `get_finding(run_id, finding_id)` | One finding with its backing signals and their evidence. |

`get_events` also takes `run_id` (older runs, while raw retention keeps their
events) and `user`.

Progress comes from the run's own log lines (`stage ...: started`,
`model call N`, `tool N/M`), written to `<data_dir>/run-progress.json` while a
run is active. A file rather than memory means a run in another process shows
up too. It needs `DAWNPATROL_LOG_LEVEL` at `INFO` (the default) or `DEBUG`.

## Running it

**Built into `serve` (one container).** The console starts as a third thread
next to the scheduler and MCP server, and talks to the local MCP server. That
server's generated token is shared in-process, so `DAWNPATROL_MCP_TOKEN` is
optional here.

```bash
DAWNPATROL_MCP_ENABLED=true          # required: the console is an MCP client
DAWNPATROL_MCP_PORT=8420
DAWNPATROL_WEB_ENABLED=true
DAWNPATROL_WEB_PORT=8421
#DAWNPATROL_WEB_PASSWORD=            # set to require a login
```

Publish the console's port alongside the MCP port, for example
`-p 192.0.2.10:8420:8420 -p 192.0.2.10:8421:8421`. Publishing only the console
also works: inside the container it reaches MCP on `127.0.0.1`.

**Standalone (`dawnpatrol web`).** Run only the console, in its own container
or on another host, pointed at an MCP server:

```bash
docker run -d --name dawnpatrol-web \
  -e DAWNPATROL_WEB_MCP_URL=http://192.0.2.10:8420/mcp \
  -e DAWNPATROL_WEB_MCP_TOKEN=<the MCP server's token> \
  -e DAWNPATROL_WEB_PORT=8421 \
  -p 8421:8421 dawnpatrol:latest web
```

It needs no database, profile or data volume.

| Setting | Default | Purpose |
|---|---|---|
| `DAWNPATROL_WEB_ENABLED` | `false` | Start the console inside `serve` |
| `DAWNPATROL_WEB_HOST` / `DAWNPATROL_WEB_PORT` | `0.0.0.0` / `8421` | Where it listens |
| `DAWNPATROL_WEB_MCP_URL` | `http://127.0.0.1:<MCP_PORT><MCP_PATH>` | Where it finds MCP |
| `DAWNPATROL_WEB_MCP_TOKEN` | `DAWNPATROL_MCP_TOKEN` | The token it sends |
| `DAWNPATROL_WEB_PASSWORD` | unset | Turns on the login page |
| `DAWNPATROL_WEB_SESSION_HOURS` | `12` | How long a login lasts |

## Starting runs

The start form, on the **Runs** page, takes:
- an optional window in hours;
- the sources to read (all enabled ones are ticked);
- a **Send the report by email** box, unticked by default.

Unticked, the run writes its report files but doesn't email, like any
MCP-started run. The run's progress appears on the same page; the report link
appears when the run finishes.

## Security

- **Password (optional).**
  - With `DAWNPATROL_WEB_PASSWORD` set, every page except the login page needs
    a session. The session cookie is signed with a per-process key, `HttpOnly`
    and `SameSite=Strict`.
  - Restarting the container signs everyone out.
  - Five wrong passwords from one address within 15 minutes lock it out for
    15 minutes.
  - The password is registered as a secret, so it can't leak into a report.
- **No password.** Anyone who can reach the port can read every report and
  start runs. The console logs a warning at startup when it listens on a
  non-loopback address without one. Bind it to a LAN address you trust, as
  with MCP.
- **Forms.**
  - Starting a run, deleting a note and signing out are POSTs carrying a form
    token that must match a cookie, and an `Origin` header (when sent) that
    must be this host.
  - That holds with or without a password: otherwise any web page you visit
    could make your browser start runs on the console.
- **Attacker-written text.** Reports and events are full of it: user agents,
  URLs, DNS names, API request bodies.
  - Every page is rendered with autoescaping, and the Runs page's script only
    ever sets `textContent`.
  - The Content-Security-Policy allows no inline script and nothing from
    other origins.
- **The MCP token never reaches the browser.**
- **No TLS of its own.** For anything beyond a trusted LAN, put it behind a
  reverse proxy that adds TLS.

### Behind a reverse proxy or tunnel

Publishing the console through a reverse proxy or a tunnel (such as Cloudflare
Tunnel) makes it reachable by anyone who can reach that hostname. Before you do:

- **Put authentication in front of it.** Use the proxy's own (for a Cloudflare
  tunnel, a Cloudflare Access policy on the hostname), `DAWNPATROL_WEB_PASSWORD`,
  or both. Without either, the internet can read your reports and start runs.
- **The login lockout counts per client address.** Behind a proxy, every
  request arrives from the proxy, so five wrong passwords lock *everyone* out
  for 15 minutes. That's annoying but safe. Proxy-level authentication avoids it.
- **Cookies are not marked `Secure`**, because the console itself only speaks
  plain HTTP. Over a TLS proxy they still travel encrypted between the browser
  and the proxy.
- **Keep the original `Host` header.** The same-site check compares the
  browser's `Origin` with the `Host` the console receives. A proxy that
  rewrites `Host` makes every form post fail with "came from another site".
  Most proxies, and Cloudflare tunnels by default, pass it through.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "Something went wrong … MCP server" on every page | The console can't reach MCP: `DAWNPATROL_MCP_ENABLED` is off, `DAWNPATROL_WEB_MCP_URL` is wrong, or the server isn't running |
| "the MCP server refused the token (HTTP 401)" | Standalone console with the wrong `DAWNPATROL_WEB_MCP_TOKEN` |
| No Notebook link | `DAWNPATROL_MCP_NOTEBOOK_ENABLED` is off on the MCP server |
| Runs page shows stages but no model or tool counts, or an empty log | `DAWNPATROL_LOG_LEVEL` is above `INFO`; progress is read from INFO lines |
| Last run shows `interrupted` | The process running it stopped (a restart mid-run); the run itself is recorded as unfinished |
| "Form expired or came from another site" | The page was open across a restart, or a proxy rewrote `Host`; reload and retry |
| Console not starting, log says it needs the MCP server | `DAWNPATROL_WEB_ENABLED=true` without `DAWNPATROL_MCP_ENABLED=true` |
