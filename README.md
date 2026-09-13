# DawnPatrol

<img src="docs/dawnpatrol_logo.svg" alt="DawnPatrol logo" width="200">

**An AI SOC analyst for your home or office network — one that reads every log,
every morning, and never gets bored, never gets tired, and never stops
learning the network it watches.**

A security operations center works because someone reviews the logs every day,
correlates what they see across sources, and knows the network well enough to
tell "routine" from "worth a second look." Most home networks and plenty of
small offices have the telemetry (a firewall, a DNS resolver) and none of the
analyst. DawnPatrol is that analyst: a scheduled network threat-hunting
pipeline in a single container. Deterministic code collects, verifies, and
reduces your telemetry; an AI agent spends its judgment on what actually
matters. One report per run, to files, email, or a webhook — waiting in your
inbox before you've had coffee, and a second, on-demand interface (below) for
when something in that report deserves a closer look.

---

## Why this exists

The obvious way to point an LLM at your logs is to paste them into a chat
window and ask "anything weird here?" That works until your firewall produces
75,000 lines and your DNS resolver produces 140,000 queries in a day — at
which point you're either truncating the evidence, paying to re-derive the
same `Counter(ports).most_common(15)` every single morning, or both. And a
model that has to re-parse epoch-vs-string timestamp quirks and pagination
edge cases from scratch each run has fewer tokens and less attention left for
the part it's actually good at: deciding what's worth your time.

DawnPatrol draws a hard boundary instead:

> **Sources fetch, analyzers count, the agent decides.**

Pagination, integrity checks, statistics, report formatting, and severity
guardrails are all plain code — testable, free to run, and identical every
day. A run's ~300,000 raw events get reduced to a few dozen metrics and
signals before the model ever sees them. The AI is spent entirely on
correlation and judgment: is this three-source cluster hammering port 8443 for
24 hours actually interesting, or is it just Tuesday? Is that DNS client with
an 80% block rate compromised, or is it just a smart TV with a lot of ad
trackers?

That reduction layer is also what makes DawnPatrol a good foundation for
**agentic security workflows**, not just a report generator. A scheduled run is
one agent working alone on a fixed cadence; an external agent connected over
MCP (below) can query the exact same reduced evidence, ask its own follow-up
questions in real SQL, and kick off a fresh, targeted investigation the moment
something looks worth a second opinion — the same judgment loop, available on
demand instead of only at 6 a.m.

In production against a real home network — LibreNMS firewall syslog (~28,000
syslog records, of which ~23,000 are firewall drop/accept lines) plus Pi-hole
DNS (~140,000 queries) per 24-hour window — a full run (collection through a
live Claude Opus 5 investigation, adjudication, and delivery) completes in
under three minutes and costs **$0.50-$1.00**, depending on effort level.
That's not a projection; that's what it actually costs to run this every day.

---

## Quick start

```bash
cp .env.example .env                      # fill in hosts and credentials
cp config/profile.example.yml config/profile.yml   # describe your network

# The container writes reports as a non-root user; a fresh bind mount needs
# to allow that before the first run (see Permissions, below).
mkdir -p out && chmod o+w out

docker compose run --rm dawnpatrol validate      # config and profile check
docker compose run --rm dawnpatrol list-plugins  # what is enabled, and why not
docker compose run --rm dawnpatrol probe         # test connectivity to sources
docker compose run --rm dawnpatrol run --stop-after analyze   # no API spend
docker compose up -d                             # start the scheduler
```

`run --stop-after analyze` executes the whole pipeline except the model call. It
prints the signals the analyzers found and costs nothing, which makes it the
right way to develop detections and to sanity-check a new deployment.

### Permissions

The container runs as a fixed non-root user, by design — the agent has no
shell and no filesystem access beyond its own mount points, and dropping root
inside the image is part of that. The tradeoff: a plain bind mount (`./out`)
keeps the host directory's original ownership, so the first write into it
fails with `Permission denied` until you widen it once with `chmod o+w out`
(shown above). The database volume doesn't need this — Docker initializes a
named volume from the image's own ownership, so it's correct from the first
run.

---

## How a run works

```
 1. PLAN        resolve the window, load the profile, open the database
 2. COLLECT     every enabled source, concurrently
 3. NORMALIZE   map raw records into one common Event model
 4. VERIFY      integrity gates; classify OK / DEGRADED / SUSPECT / FAILED
 5. PERSIST     write events; update the long-term entity baseline
 6. ANALYZE     analyzers -> metrics and signals
 7. INVESTIGATE the agent loop: evidence bundle in, structured findings out
 8. ADJUDICATE  validate findings, enforce guardrails, roll up status
 9. RENDER      plaintext / markdown / json
10. DELIVER     every enabled output
11. CHECKPOINT  persist metrics, findings, watchlist; purge by retention
```

Only stage 7 calls a model.

---

## Configuration

Two places, and only two:

- **Environment variables** — credentials, endpoints, schedule, budgets. Every
  secret also accepts a `_FILE` suffix (`..._PASSWORD_FILE=/run/secrets/x`) for
  Docker secrets. See `.env.example`.
- **`config/profile.yml`** — your network: zones, hosts, policy, known quirks.
  Gitignored; `config/profile.example.yml` is the tracked template.

Nothing in the source tree contains an address, hostname, or credential, which
is what makes the repo publishable.

The profile is more than documentation. Zones drive per-segment analysis,
`approved_resolvers` turns DNS bypass into a HIGH signal, and
`nat_attribution_limited_behind` makes DawnPatrol say "from behind the gateway"
instead of naming a device it cannot actually see.

### Database

SQLite by default, inside `DAWNPATROL_DATA_DIR`, with nothing to configure.
Setting **both** `DAWNPATROL_DB_HOST` and `DAWNPATROL_DB_USER` switches to
MySQL automatically — the override is credential-driven, so there is no flag to
remember. A full `DAWNPATROL_DB_URL` overrides both.

Retention is split by cost: raw events age out in 7 days (configurable), while a
narrow long-term slice of DNS and flow records persists for 180 days. That slice
is what makes `dawnpatrol hunt --domain evil.example --days 180` possible when an
IOC surfaces next month.

### Model provider

Providers are plugins. `anthropic` is the default; `openai_compatible` points at
any server speaking `/v1/chat/completions` — Ollama, LM Studio, vLLM, LiteLLM,
Open-WebUI:

```bash
DAWNPATROL_AI_PROVIDER=openai_compatible
DAWNPATROL_AI_BASE_URL=http://10.0.0.30:11434
DAWNPATROL_AI_MODEL=qwen2.5:32b
```

Cost is bounded by `DAWNPATROL_AI_MAX_COST_USD`, `..._MAX_TOOL_CALLS`, and
`..._EFFORT`. Tripping a ceiling degrades the run to a statistics-only report —
never to no report at all.

---

## Extending it

Five plugin folders. Drop in a file, set its environment variables, and it is
discovered automatically. Each folder has a `TEMPLATE.py` to copy.

| Folder | Add one to... | Guide |
|---|---|---|
| `dawnpatrol/sources/` | read a new telemetry system | [docs/components/sources.md](docs/components/sources.md) |
| `dawnpatrol/analyzers/` | detect a new pattern | [docs/components/analyzers.md](docs/components/analyzers.md) |
| `dawnpatrol/enrichment/` | add external context on IPs or domains | [docs/components/enrichment.md](docs/components/enrichment.md) |
| `dawnpatrol/outputs/` | deliver somewhere new | [docs/components/outputs.md](docs/components/outputs.md) |
| `dawnpatrol/providers/` | use a different model backend | [docs/components/providers.md](docs/components/providers.md) |

A plugin enables itself when all of its declared `requires_env` variables are
present — there is no registry to edit and no way for a plugin to exist but
never be wired up. `dawnpatrol list-plugins` shows what is on and what each
disabled one is waiting for.

Analyzers are pure functions over the event store: no network, no model calls.
That is what makes them testable against fixtures and fast to iterate on.
Ships today with two sources (LibreNMS syslog, Pi-hole DNS) and seven
analyzers (firewall volume, firewall pattern classification, DNS anomalies,
beaconing, per-segment review, cross-source correlation, and baseline delta) —
the shape is built for a third source and an eighth analyzer to be a single
new file, not a rewrite. The detection self-test that proves those analyzers
are actually working (not just running) is its own system — see
[docs/components/canaries.md](docs/components/canaries.md) — and the network
documentation that gives every finding its context is `profile.yml` — see
[docs/components/profile.md](docs/components/profile.md).

---

## Why a report can be trusted

Four mechanisms, all structural rather than advisory:

**Findings must trace to data.** Every finding cites at least one analyzer
signal, and the adjudicator rejects one that does not. There is no path to
reporting something the deterministic layer never observed.

**Guardrails are code.** Reputation alone cannot create a finding. Severity
cannot exceed its strongest supporting signal by more than one level. CRITICAL
requires local evidence, not an external score. Country is never a severity
input. Each is a validator with a test, not a line in a prompt — and every clamp
is disclosed in the report.

**Empty is not the same as absent.** A source returning zero rows triggers its
own differential probes. It becomes `FAILED` only when probe evidence supports
it, and `SUSPECT` otherwise — so a malformed query can never be reported as
"monitoring is blind".

**The pipeline proves it is still looking.** Each run injects synthetic activity
in reserved documentation ranges and asserts the analyzers detect it. The header
reads `Detection self-test: 2/2 canaries detected`. A failed canary is itself a
CRITICAL finding, because it means every GREEN since the last successful check
is unverified. Canary events are analyzed in an isolated pass, so they never
touch a reported statistic.

None of this is aspirational — it's what a real deployment produces every
morning: a report that names its own blind spots (a segment behind a NAT
gateway with no per-device visibility, a DNS source that came back short of
its own reported total) right alongside its findings, instead of a
confident-sounding wall of text with no way to check its work.

---

## Operating it

```bash
dawnpatrol run --print                  # run now and show the report
dawnpatrol run --dry-run                # everything except delivery
dawnpatrol runs                         # recent run history
dawnpatrol canary                       # last detection self-test
dawnpatrol hunt --domain x --days 180   # retrospective IOC search
dawnpatrol suppress --taxonomy scan.persistent_prober \
    --entity 203.0.113.45 --reason "my own scanner" --days 90
dawnpatrol suppressions                 # list active suppressions
```

Suppressions carry a mandatory expiry, and matching findings move to a report
appendix rather than being deleted — so a tuned-out pattern that changes
character is still visible.

Delivery policy is per output:
`DAWNPATROL_OUTPUT_SMTP_RUN_WHEN=ALWAYS|NEVER|IMPORTANT|AMBER,RED`. Email
defaults to daily, because silence is indistinguishable from a dead agent;
webhooks default to `IMPORTANT`, because a channel that pings every morning gets
muted.

---

## Agentic workflows: external agent access (MCP)

The scheduled email is the everyday case: one report, once a day, no action
needed to receive it. Sometimes that report says something that deserves a
closer look, and this is how a *second* agent goes and looks — your own
Claude session, an incident-response bot, anything that speaks MCP — without
waiting for tomorrow's run or re-deriving context DawnPatrol already has. It's
the difference between a report that tells you something looks strange and an
agent that can go find out why, right now, using the same evidence the
scheduled analyst already built.

Set `DAWNPATROL_MCP_ENABLED=true` and DawnPatrol exposes a small,
mostly-read-only tool surface over streamable HTTP, for any MCP-capable agent
to connect to directly:

| Tool | Does |
|---|---|
| `list_reports` / `get_latest_report` / `get_report` | Read past reports - the same files the `file` output writes. |
| `describe_event_schema` / `query_events` | The same guarded read-only SQL the investigation agent uses: one `SELECT`, an allowlisted set of tables, a row cap. |
| `get_metric_history` | A metric's time series, for trend questions. |
| `get_network_profile` | The zones/hosts/policy/quirks documentation from `profile.yml`. |
| `list_source_plugins` | Which sources are enabled - the valid names for the next tool. |
| `trigger_analysis` | Collect fresh data and run a full analysis now, optionally scoped to specific sources, **without emailing the result**. Real API spend, same pipeline a scheduled run would use. |

This is a second door onto capabilities that already exist, not a new set of
them: `trigger_analysis` runs the identical `Runner` a scheduled run does,
`query_events` runs through the identical validator the in-run agent's SQL
tool does, and reports come from the identical files the `file` output
writes. Nothing here can email anyone, touch the filesystem outside the
report directory, or reach a network destination DawnPatrol didn't already
reach.

It is the one thing in this design that listens, so it is off by default and
authenticates every request with a bearer token
(`Authorization: Bearer <token>`) - set `DAWNPATROL_MCP_TOKEN` yourself, or
leave it unset and a token is generated for that process and printed once to
the container logs at startup. Bind it to a specific address
(`DAWNPATROL_MCP_HOST`), not a public one, and treat the token like any other
credential in `.env`.

See [docs/components/mcp-server.md](docs/components/mcp-server.md) for the
full tool reference, deployment guidance, and a real example of the detection
self-test correctly catching a gap during an ad hoc, source-restricted run.

---

## Security notes

The agent has no shell, no filesystem access, and no delivery tool. Its only
outbound effects are budgeted reputation lookups. Report recipients come from
environment variables and cannot be influenced by log content — which matters,
because log content is attacker-influenced by definition and arrives fenced and
labelled as untrusted data.

Its SQL tool is read-only by construction: single `SELECT`, an allowlisted set
of tables, an injected row cap, and no access to configuration or delivery
tables. For MySQL, point it at a read-only database user as well.

Every rendered report is scanned for configured secret values before any output
runs; a match aborts delivery.

The container itself drops root before running your code, per the Dockerfile's
`USER` directive — the non-root uid is also why the `out/` bind mount needs the
one-time permission fix under Quick start.

---

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev,all]"
.venv/bin/pytest -q
.venv/bin/ruff check dawnpatrol tests
```

202 tests, fully offline — no network, no API key, no spend — including an
end-to-end pipeline exercise against a stubbed provider. Tests cover the parsing
traps that previously caused silent data loss, the false-positive guards
(benign traffic that must *not* be reported), the renderer's format contract
(plaintext, markdown, json, and html - including that attacker-influenced text
is escaped, not passed through as markup), every adjudication guardrail, and
the MCP server's tool logic and bearer-auth middleware. CI
(`.github/workflows/ci.yml`) runs the same lint and test suite on every push
and pull request, across Python 3.11-3.13.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the full systems-level design: the
  pipeline stage by stage, the core data model, state and persistence, the AI harness
  and prompt caching, guardrails, the cost model measured against real production runs,
  and which design decisions were made and why.
- [`docs/components/`](docs/components/README.md) — a tutorial-style guide per
  component (sources, analyzers, enrichment, outputs, providers, canaries, the network
  profile, the MCP server), each ending with a worked example of building your own.
  Start here if you want to extend DawnPatrol rather than just run it.

## License

MIT — see [LICENSE](LICENSE).
