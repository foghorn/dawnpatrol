# DawnPatrol Architecture

**Status:** Implemented and in production (Phases 1-4.5 complete; see §15)
**Last updated:** 2026-09-13

This document describes the system as it is actually built, not as it was originally
proposed. Where an earlier draft described an open design question, this revision
records the decision that was made and why (§16). For a tutorial-style walkthrough of
any one plugin type - with a worked example of building your own - see
`docs/components/`; this document is the systems-level view of how the pieces fit
together.

A single-container, scheduled threat-hunting pipeline. Deterministic code does the
collection, normalization, and statistics; an AI agent does the judgment. Everything
environment-specific lives in configuration, so the repo can be published publicly.

---

## 1. Goals and non-goals

### Goals

1. **One container, one schedule.** `docker run` with a cron expression in an env var.
   No Open-WebUI, no ephemeral-container script rebuilding, no skills-as-credential-store.
2. **Deterministic mechanics, AI judgment.** Pagination, integrity checks, aggregation,
   formatting, and guardrail enforcement are code. The model spends its tokens on
   correlation and severity calls, not on re-deriving a regex every morning.
3. **Publishable.** No IPs, tokens, hostnames, or network topology in the source tree.
4. **Atomic and extensible.** Drop a `.py` file into a folder, it gets picked up. No
   registration lists to edit, no core code to touch.
5. **Real state.** Trends and baselines come from a persistent database, not from
   "search your notes for a title starting with DawnPatrol State".
6. **Bounded cost.** Hard token, dollar, and tool-call ceilings enforced by the harness.

### Non-goals

- Real-time alerting. This is a scheduled batch analyst, not an IDS.
- Being a SIEM. It reads from your existing telemetry; it does not replace it.
- Multi-tenant / multi-network. One deployment watches one network. (Run two containers.)
- A UI. Output is files and delivery plugins.

---

## 2. What actually changes from the current system

The existing agent prompt is ~1,900 lines. Most of it is not analysis guidance — it is
compensation for the model having to redo mechanical work every run. Here is where each
category of that knowledge lands in the new design.

| Current prompt content | Lines | New home |
|---|---|---|
| LibreNMS `from`/`to` epoch-vs-string trap, differential test, baseline sanity checks | ~120 | `sources/librenms_syslog.py` + its tests |
| Pi-hole `cursor` no-op, `errors="replace"`, `recordsFiltered` loop target, integrity gates | ~150 | `sources/pihole_dns.py` + its tests |
| iptables regex, protocol-number normalization, program bucketing | ~40 | `sources/librenms_syslog.py` normalizer |
| Hourly distribution, top-N by hit and by unique-source, port callouts | ~60 | `analyzers/firewall_volume.py` |
| Prober / sweep / conntrack-return / stepped-TTL classification heuristics | ~50 | `analyzers/firewall_patterns.py` |
| DGA detection, newly-seen domains, block-rate math, status taxonomy | ~70 | `analyzers/dns_anomalies.py` |
| AbuseIPDB 25-IP budget, whitelist trap, score-vs-reports rule | ~90 | `enrichment/abuseipdb.py` (budget is a tool limit, not a request) |
| ismalicious `classification.primary` false-positive trap | ~40 | `enrichment/ismalicious.py` |
| Plain-text/ASCII/72-column email contract, template, pre-send checklist | ~300 | `render/plaintext.py` + a lint test |
| Severity guardrails ("reputation may move by at most one level") | ~60 | `adjudicate.py`, enforced post-hoc in code |
| Cross-run state via notes | ~40 | `state.db` (SQLite on a volume) |
| Network inventory and segment expectations | ~50 | `profile.yml` (mounted config) |
| **Actual analytical guidance the model still needs** | **~150** | `agent/prompts/system.md` |

Roughly 90% of the prompt becomes code, config, or tests. What remains is the part a
model is genuinely good at: looking at pre-computed signals across sources and deciding
what matters.

Two consequences worth naming up front:

- **The formatting rules stop being a prompt problem.** The model never emits the report
  body. It emits structured findings; a renderer produces the 72-column ASCII. The
  "ABSOLUTELY FORBIDDEN: em-dashes, emoji, pipe tables" section disappears entirely,
  replaced by a unit test that asserts the rendered output is 7-bit ASCII with no line
  over 72 characters.
- **The guardrails stop being requests.** "Never enrich more than 25 IPs" becomes a tool
  that returns an error on the 26th call. "Reputation may not create a finding" becomes a
  validator that rejects a finding whose only evidence is a reputation score.

---

## 3. Pipeline

Ten stages. Stages 1-6 and 8-10 are fully deterministic; only stage 7 calls the model.

```
  1. PLAN        resolve run window, load profile, open state DB, load baseline
  2. COLLECT     run every enabled source plugin concurrently -> raw records
  3. NORMALIZE   map raw records to the common Event model
  4. VERIFY      per-source integrity gates; classify OK/DEGRADED/FAILED (blocking)
  5. PERSIST     write events to run.db (SQLite); update baseline tables in state.db
  6. ANALYZE     run every analyzer plugin -> Metrics + Signals
  7. INVESTIGATE agent loop: evidence bundle in, structured Analysis out
  8. ADJUDICATE  validate findings, enforce guardrails, compute overall status
  9. RENDER      Report -> text / markdown / html / json
 10. DELIVER     run every enabled output plugin; record results
 11. CHECKPOINT  persist run summary, metrics, findings, watchlist for tomorrow
```

Every stage writes a structured record to `state.db` so a failed run is debuggable
without re-running it. `dawnpatrol run --stop-after analyze` is a first-class mode — it
gives you the full evidence bundle with zero API spend, which is how you develop
analyzers.

### Why stage 6 exists (the one addition to your folder proposal)

You proposed three plugin folders: sources, enrichment, outputs. I am proposing a
fourth, `analyzers/`, and it carries most of the value of the redesign.

The problem it solves: a day of this network is ~300,000 events (≈75k syslog over 48h
plus ≈222k DNS over 24h). That does not fit in a prompt, and paying a model to compute
`Counter(ports).most_common(15)` is exactly the waste you want to eliminate. Analyzers
are the reduction layer that turns 300,000 events into ~40 pre-computed signals and a
few dozen metrics — roughly 25k tokens of dense, numeric evidence.

It is also the right extension point for detection logic. Adding "flag any host that
starts resolving a new TLD it has never used" should be a new file in `analyzers/`, not a
paragraph appended to a system prompt where it competes for attention with 80 other
paragraphs. Detection logic in code is testable against fixtures; detection logic in a
prompt is not.

The split in one line: **sources fetch, analyzers count, the agent decides.**

---

## 4. Repository layout

```
dawnpatrol/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── README.md
├── config/
│   └── profile.example.yml         # network topology template, no real values
├── dawnpatrol/
│   ├── __init__.py
│   ├── cli.py                      # run / list-plugins / validate / render / probe
│   ├── scheduler.py                # in-process cron loop
│   ├── config.py                   # env + YAML -> typed settings
│   ├── profile.py                  # network topology model
│   ├── registry.py                 # plugin discovery
│   ├── models.py                   # Event, Metric, Signal, Finding, Report
│   ├── window.py                   # run-window arithmetic
│   ├── store.py                    # run.db (events) + state.db (history)
│   ├── verify.py                   # source health classification
│   ├── adjudicate.py               # guardrail enforcement, status rollup
│   ├── budget.py                   # token / dollar / call ceilings
│   ├── canary.py                   # synthetic-signal self-validation
│   ├── runner.py                   # pipeline orchestration
│   ├── agent/
│   │   ├── harness.py              # Anthropic tool-runner loop
│   │   ├── tools.py                # query_events, enrich_*, get_history, ...
│   │   ├── bundle.py               # evidence bundle assembly
│   │   ├── schema.py               # structured-output JSON schema for Analysis
│   │   └── prompts/
│   │       ├── system.md
│   │       └── task.md
│   ├── render/
│   │   ├── plaintext.py            # 72-col 7-bit ASCII (the email contract)
│   │   ├── markdown.py
│   │   ├── html.py
│   │   └── json_report.py
│   ├── sources/                    # ── PLUGIN FOLDER ──
│   │   ├── librenms_syslog.py
│   │   ├── pihole_dns.py
│   │   └── TEMPLATE.py
│   ├── analyzers/                  # ── PLUGIN FOLDER ──
│   │   ├── firewall_volume.py
│   │   ├── firewall_patterns.py
│   │   ├── dns_anomalies.py
│   │   ├── beaconing.py
│   │   ├── segment_review.py
│   │   ├── correlation.py
│   │   ├── baseline_delta.py
│   │   └── TEMPLATE.py
│   ├── enrichment/                 # ── PLUGIN FOLDER ──
│   │   ├── abuseipdb.py
│   │   ├── ismalicious.py
│   │   └── TEMPLATE.py
│   └── outputs/                    # ── PLUGIN FOLDER ──
│       ├── file_report.py
│       ├── smtp_email.py
│       ├── webhook.py
│       └── TEMPLATE.py
└── tests/
    ├── fixtures/                   # recorded, scrubbed API responses
    ├── test_sources/
    ├── test_analyzers/
    ├── test_render/                # ASCII + width + template lints
    └── test_adjudicate/            # guardrail enforcement
```

---

## 5. Core data model

One flat `Event` type, not a per-source shape. This is the decision that makes
cross-source correlation possible at all: the IoT-device-bypassing-Pi-hole finding only
works if a firewall event and a DNS event agree on what `src_ip` means.

```python
class EventKind(StrEnum):
    FIREWALL = "firewall"; DNS = "dns"; SYSTEM = "system"
    AUTH = "auth"; IDS = "ids"; FLOW = "flow"; HTTP = "http"; OTHER = "other"

@dataclass(frozen=True, slots=True)
class Event:
    ts: datetime                  # UTC, tz-aware, required
    source: str                   # plugin name
    kind: EventKind
    dedup_key: str                # stable per-source id for idempotent re-collection

    # network (firewall / flow)
    src_ip: str | None = None;   dst_ip: str | None = None
    src_port: int | None = None; dst_port: int | None = None
    proto: str | None = None     # normalized: tcp/udp/icmp/igmp/...
    action: str | None = None    # drop/accept/reject/allow/block
    iface_in: str | None = None; iface_out: str | None = None
    ttl: int | None = None;      pkt_len: int | None = None

    # dns
    domain: str | None = None;   qtype: str | None = None
    blocked: bool | None = None; block_reason: str | None = None
    upstream: str | None = None; client_ip: str | None = None

    # host / system
    device: str | None = None;   program: str | None = None
    severity: str | None = None; message: str | None = None
    user: str | None = None

    # derived at normalize time from profile.yml
    src_zone: str | None = None; dst_zone: str | None = None

    raw: dict = field(default_factory=dict)   # kept in SQLite, never bulk-sent to the model
```

`src_zone` / `dst_zone` are assigned by matching IPs against the segments in
`profile.yml`. That is what lets an analyzer say "IoT → external on a non-vendor port"
without hardcoding `192.168.50.0/24` anywhere in the source tree.

Downstream types:

```python
@dataclass
class Metric:                     # deterministic; goes straight to the report
    key: str                      # "fw.drops.total", "dns.block_rate"
    value: float | int | str
    unit: str | None
    section: str                  # which report section it belongs to
    prior: float | None = None    # auto-filled from state.db
    delta_pct: float | None = None

@dataclass
class Signal:                     # a candidate finding, computed deterministically
    id: str                       # stable slug: "fw.prober.203.0.113.45.22"
    analyzer: str
    title: str
    taxonomy: str                 # "scan.persistent_prober", "dns.dga_suspect"
    entities: list[Entity]        # typed subjects: ip / domain / host / port / device
    severity_hint: Severity       # deterministic prior, the agent may adjust
    confidence: float             # 0-1
    evidence: dict                # numbers and quoted samples only
    support: list[str]            # event dedup_keys, for drill-down
    first_seen: date | None       # from state.db
    days_recurring: int = 0

@dataclass
class Finding:                    # produced by the agent, validated by adjudicate.py
    id: str; title: str; severity: Severity; confidence: Confidence
    zone: str; taxonomy: str
    what: str; why: str; not_this: str; action: str
    signal_ids: list[str]         # REQUIRED — must reference at least one Signal
    evidence_kinds: set[str]      # {"local_behavior", "reputation", "baseline_delta"}
    entities: list[Entity]
    enrichment: list[EnrichmentRef]
```

`Finding.signal_ids` being required is a structural anti-hallucination measure: a finding
that does not trace to at least one deterministically-computed signal is rejected by the
validator, not merely discouraged by a prompt rule.

---

## 6. Plugin contracts

All four folders use the same discovery mechanism: `pkgutil.iter_modules` over the
package directory, import each module, collect subclasses of the relevant ABC. Files
starting with `_` or named `TEMPLATE.py` are skipped.

```python
# registry.py
def discover(package, base_class) -> dict[str, type]:
    for _, name, _ in pkgutil.iter_modules(package.__path__):
        if name.startswith("_") or name == "TEMPLATE":
            continue
        importlib.import_module(f"{package.__name__}.{name}")
    return {c.name: c for c in all_subclasses(base_class)}
```

**Enablement is automatic and env-driven.** A plugin declares its required env vars; if
all of them are set, it is enabled. No registry file, no `ENABLED_PLUGINS` list to
maintain. `DAWNPATROL_DISABLE=pihole_dns` is the escape hatch, and `DAWNPATROL_SOURCES=...`
pins an explicit set when you want determinism.

### 6.1 Sources

```python
class Source(ABC):
    name: str                          # "librenms_syslog"
    kinds: set[EventKind]
    requires_env: set[str]             # gates auto-enablement
    default_window_hours: int = 48
    max_window_hours: int | None = None   # e.g. 24 for Pi-hole retention

    def configure(self, env: Mapping[str, str], profile: Profile) -> None: ...

    @abstractmethod
    def collect(self, window: Window, ctx: RunContext) -> CollectionResult: ...

    @abstractmethod
    def self_test(self, ctx: RunContext) -> list[Probe]: ...

    def health(self, result: CollectionResult, probes: list[Probe]) -> SourceHealth: ...
```

`CollectionResult` carries `events`, `reported_total`, `unique_count`, `span_hours`,
`pages`, and `errors`. `verify.py` applies the generic gates (unique ≈ reported total,
span ≈ requested window, non-zero) and calls the source's own `health()` for anything
source-specific.

`self_test()` is the differential test from the LibreNMS skill, promoted to a first-class
plugin capability. When a source returns zero records, the framework **automatically**
runs `self_test()` before classifying it, and the probe results are attached to the run
record verbatim. This is the mechanism that makes "the API returned zero rows" and "the
device stopped forwarding" distinguishable without asking a model to remember to check:

```python
# sources/librenms_syslog.py
def self_test(self, ctx):
    return [
        self.probe("no-filter",       f"/logs/syslog/{self.primary}?limit=1"),
        self.probe("control-device",  f"/logs/syslog/{self.controls[0]}?{ctx.window.qs()}&limit=1"),
        self.probe("narrow-window",   f"/logs/syslog/{self.primary}?{ctx.window.last_hour().qs()}&limit=1"),
        self.probe("auth-check",      "/devices?limit=1"),
    ]
```

Health states: `OK` / `DEGRADED` (partial but usable, e.g. Pi-hole's ~24h retention
against a 48h request) / `SUSPECT` (zero rows, probes inconclusive) / `FAILED` (zero rows,
probes confirm). **`SUSPECT` never renders as "monitoring is blind"** — the renderer has
distinct language per state, so the false-outage failure mode is structurally impossible.

Window handling is per-source. A source declaring `max_window_hours = 24` is clamped by
the framework, and the clamp is recorded as a known limit rather than a shortfall. This
kills the "never present a 24h DNS total alongside a 48h firewall total without labeling
them" rule — the labels are generated from the window each source actually achieved.

See `docs/components/sources.md` for the full contract, both shipped sources walked
through line by line, and a worked example of adding a third.

### 6.2 Analyzers

```python
class Analyzer(ABC):
    name: str
    requires_kinds: set[EventKind]     # skipped if no source provided these
    requires_sources: set[str] = set() # optional harder dependency

    @abstractmethod
    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        """Returns Metrics and Signals. Pure: no network, no model calls."""
```

`EventQuery` is a thin, typed query API over the run's SQLite — `q.count(kind=...,
action="drop", group_by="dst_port")`, `q.top(..., n=15, by="unique:src_ip")`,
`q.hourly(...)` — so analyzers stay short and readable. They never touch the network,
which makes them trivially testable against fixtures and fast to iterate on.

`baseline` exposes history: `baseline.first_seen(domain)`, `baseline.metric_series(key,
days=30)`, `baseline.is_novel_ip(ip)`. Newly-seen-domain detection becomes a real
database query instead of a diff against a note the model wrote yesterday.

Analyzers are independent and run in dependency order only where declared. Adding one is
a single file with one method.

See `docs/components/analyzers.md` for the `EventQuery`/`Baseline` APIs in full and a
worked example of adding a new detection.

### 6.3 Enrichment

```python
class Enricher(ABC):
    name: str
    subject_types: set[str]            # {"ip"} / {"domain"} / {"url"} / {"hash"}
    requires_env: set[str]
    default_budget: int                # lookups per run
    cache_ttl: timedelta               # per-subject cache lifetime
    batch_size: int = 1

    @abstractmethod
    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]: ...

    def prefilter(self, subjects: list[str]) -> list[str]:
        """Drop subjects this source cannot usefully answer (RFC1918, known-good TLDs)."""
```

`Enrichment` is a normalized verdict — `score` (0-100), `verdict`
(benign/unknown/suspicious/malicious), `whitelisted`, `categories`, `attributes`,
`raw` — so an analyzer or the renderer can consume any enricher without knowing whether
it was AbuseIPDB or ismalicious or something you add next month.

Three things the framework handles so no plugin (and no prompt) has to:

- **Caching.** Every lookup is cached in `state.db` keyed by `(enricher, subject)` with a
  TTL. Your top scanner IPs are the same every single day; after week one, most lookups
  are free. This alone is a large share of the current run's enrichment cost.
- **Budget.** Enforced at the tool boundary. The 26th lookup returns a structured
  "budget exhausted" result. The model cannot overspend, so the prompt does not need to
  ask it not to.
- **Prefiltering.** `abuseipdb.prefilter()` drops non-public addresses;
  `ismalicious.prefilter()` drops a configurable known-good domain list. Wasted lookups
  are prevented, not discouraged.

The AbuseIPDB score-vs-`totalReports` trap is handled by simply not surfacing
`totalReports` in the normalized `Enrichment` at all. It lives in `.raw` for audit. The
model cannot misreport a number it is not given.

See `docs/components/enrichment.md` for the full contract and a worked example of
adding a new reputation source.

### 6.4 Outputs

```python
class Output(ABC):
    name: str
    renderer: str                      # "plaintext" | "markdown" | "html" | "json"
    requires_env: set[str]
    run_when: set[Status] = {GREEN, AMBER, RED}   # env-overridable

    @abstractmethod
    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult: ...
```

Renderers are shared library code, not plugins — an output picks one by name. This
avoids every new delivery destination re-implementing the ASCII contract, which is the
exact failure the current email-format skill exists to prevent. Write the renderer once,
test it once, and `smtp_email`, `file_report`, and a future `s3_upload` all get it right.

`run_when` makes "page me only on AMBER/RED, but always write the file" a config
setting rather than prompt logic.

Shipped outputs: `file_report` (writes `${OUTPUT_DIR}/YYYY-MM-DD/report.{txt,json}`, plus
`html` if configured, and a `latest.*` copy of each), `smtp_email`, and `webhook`
(generic JSON POST — ntfy, Slack, Discord, Home Assistant). A future `healthchecks_ping`
for dead-man's-switch monitoring remains a natural next output, not yet built.

See `docs/components/outputs.md` for the full contract, `run_when` policy in detail, and
a worked example of adding a new delivery destination.

---

## 7. State and persistence

Two SQLite databases on one mounted volume. This is the direct fix for "the container is
ephemeral so scripts get recreated every day".

**`run.db`** — per-run, disposable, `${DATA_DIR}/runs/<run_id>/run.db`. One `events`
table plus indexes on `(ts)`, `(kind, ts)`, `(src_ip)`, `(dst_port)`, `(domain)`,
`(client_ip)`. Retained for `DAWNPATROL_RUN_RETENTION_DAYS` (default 7) so you can re-run
analysis or let the agent drill into yesterday. At ~300k rows this is roughly 60-120 MB
per run.

Raw events age out, but a **narrow long-term slice** does not. `state.db` keeps DNS
resolutions and, once a flow source exists, connection tuples as thin rows for
`DAWNPATROL_IOC_RETENTION_DAYS` (default 180) — a few bytes each, no message payload. This
is what makes retrospective hunting possible: when an IOC surfaces next month,
`dawnpatrol hunt --domain evil.example --days 180` answers whether anything here ever
touched it. Detection is usually retroactive; the store should assume that.

**`state.db`** — permanent, `${DATA_DIR}/state.db`:

| Table | Purpose |
|---|---|
| `runs` | run_id, window, status, per-stage timings, token/cost accounting |
| `source_health` | per-run, per-source: counts, span, health state, probe results |
| `metrics` | long metric series — powers real 30/90-day trends, not just yesterday |
| `findings` | every finding ever emitted; enables "day 4 of this pattern" and dedup |
| `entities` | first_seen / last_seen / occurrence counts for IPs, domains, hosts |
| `enrichment_cache` | `(enricher, subject)` -> normalized verdict + TTL |
| `watchlist` | items carried forward with an expiry, set by the agent or by a human |
| `suppressions` | tuned-out patterns: matcher, reason, author, expiry |
| `canaries` | per-run synthetic-signal injections and whether each was detected |
| `deliveries` | per-output success/failure, for "was the report actually sent" |

The `entities` table is what makes novel-domain and novel-IP detection deterministic and
genuinely reliable. `findings` history is what makes trend language honest — "RECURRING
(day 4)" is a database count, not a recollection.

---

## 8. The AI harness

### 8.1 Model and loop

Claude Opus 5 (`claude-opus-5`) via the official `anthropic` Python SDK, driven by a
hand-written loop (`providers/anthropic_provider.py`) rather than the SDK's tool runner -
a deliberate choice, not an oversight: the harness needs per-turn budget checks, cost
accounting mid-loop, and a terminal-tool break, and keeping the loop's shape identical to
the `openai_compatible` provider's makes both easy to reason about side by side. Every
provider is a plugin (`docs/components/providers.md`), so this loop shape is one
implementation among however many backends get added, not baked into the harness itself.

Configuration per run:

- `thinking: {"type": "adaptive"}` — this is genuinely reasoning-heavy work.
- `output_config: {"effort": ...}` — the primary cost/quality dial,
  `DAWNPATROL_AI_EFFORT`, default `high`.
- `output_config.task_budget` (beta `task-budgets-2026-03-13`) — gives the model a token
  ceiling it can pace itself against, so it wraps up gracefully rather than being cut off
  mid-investigation.
- Streaming, since `max_tokens` is large.
- Server-side refusal fallbacks (`betas: ["server-side-fallback-2026-07-01"]`,
  `fallbacks: "default"`) — security log content occasionally trips classifiers, and a
  refused run should degrade to a fallback model rather than produce no report.

`DAWNPATROL_AI_MODEL` is an env var. Nothing in the pipeline depends on the model choice;
`claude-haiku-4-5` is a perfectly reasonable setting for a quiet network or for testing.

The model backend itself is a plugin (`dawnpatrol/providers/`, discovered the same way as
sources/analyzers/enrichers/outputs): `anthropic_provider.py` ships as the default, and
`openai_compatible.py` points at any `/v1/chat/completions` server — Ollama, LM Studio,
vLLM, a local model is one environment variable away, not a code change. See
`docs/components/providers.md` for the `Provider` contract and a worked example of
adding a new backend.

### 8.2 Prompt structure and caching

Ordered for maximum cache hit rate — render order is `tools` → `system` → `messages`, so
stable content goes first:

```
tools            [stable, cached]     tool definitions
system           [stable, cached]     system.md: role, severity taxonomy, epistemics
                 [semi-stable, cached] profile.yml rendered as network context
messages[0]      [volatile]           evidence bundle + task
messages[1..n]   [volatile]           tool call / result turns
```

Cache breakpoint after the profile block. The system prompt plus profile is ~8-10k
tokens that are byte-identical every day until you edit the profile, so day 2 onward
reads them at the cache rate. Crucially, **no timestamps, run IDs, or counts appear
before the breakpoint** — that is the classic silent cache invalidator, and
`usage.cache_read_input_tokens` is asserted non-zero in the run record so a regression
is visible rather than silently expensive.

### 8.3 Tools

| Tool | Purpose | Guard |
|---|---|---|
| `describe_schema()` | events table columns, kinds present, row counts | — |
| `query_events(sql)` | read-only SQL against `run.db` | single `SELECT`, read-only connection, injected `LIMIT`, 5s timeout, byte cap on results |
| `sample_events(signal_id, n)` | pull the raw events backing a signal | n ≤ 50 |
| `enrich_ip(ips)` / `enrich_domain(domains)` | reputation lookups | budget + cache + prefilter enforced here |
| `get_metric_history(key, days)` | trend series from `state.db` | — |
| `get_entity_history(entity)` | first_seen, occurrences, prior findings | — |
| `get_watchlist()` | items carried forward | — |

`query_events` as read-only SQL rather than a fixed set of canned queries is a deliberate
choice: it lets the model chase a hypothesis it forms mid-run ("which clients queried
this domain, and did any of them also appear in the drop log?") without us having to
anticipate the question. The safety comes from the connection being genuinely read-only
(`file:run.db?mode=ro&immutable=1`), single-statement, timed out, and row-capped — not
from asking the model to behave.

Note what is *not* a tool: there is no shell, no filesystem access, no network fetch, and
no send-email tool. The model's only outbound effects are enrichment lookups against two
specific APIs. Delivery happens after adjudication, in code. This is a meaningful
reduction in blast radius compared to an agent that could email arbitrary recipients.

### 8.4 Structured output

The agent returns JSON conforming to a schema (`output_config.format`), not prose:

```jsonc
{
  "executive_summary": "string, 2-3 sentences",
  "findings": [ { "title": "...", "severity": "HIGH", "confidence": "high",
                  "signal_ids": ["fw.prober.203.0.113.45.22"],
                  "evidence_kinds": ["local_behavior", "reputation"],
                  "what": "...", "why": "...", "not_this": "...", "action": "..." } ],
  "section_narratives": { "perimeter": "...", "dns": "...", "router": "...",
                          "segments": {"lan": "...", "iot": "...", "dmz": "..."} },
  "trend_notes": [ {"kind": "ESCALATING", "text": "...", "signal_ids": [...]} ],
  "recommended_actions": [ {"priority": 1, "text": "...", "command": "..."} ],
  "watchlist_updates": [ {"entity": "...", "reason": "...", "expires_days": 7} ],
  "data_quality_notes": [ "..." ]
}
```

The model writes judgment and prose fragments. It never writes headings, never writes
numbers that belong to a metric, and never writes the report envelope. All the statistics
sections are rendered from `Metric` objects the analyzers produced, which means **every
number in the report traces to code by construction** — the current prompt's rule 3
("numbers must come from the actual parsed datasets") stops being a rule and becomes a
property of the system.

### 8.5 Cost model

Measured against a real deployment (~28k firewall records, ~140k DNS queries per 24h
window), not projected. Opus 5 at $5/MTok input, $25/MTok output, cache reads at
$0.50/MTok.

| Run | Effort | Model calls | Input | Output | Cache read | Cost |
|---|---|---|---|---|---|---|
| Scheduled, medium effort | `medium` | 5-6 | ~131k | ~11.8k | ~30.5k | **$0.51-0.56** |
| Scheduled, high effort | `high` | 6 | ~273k | ~14.4k | ~61k | **$0.97-1.21** |
| MCP-triggered, one source only | `high` | 5 | - | - | - | $0.56 |

Cache reads are nonzero from the very first multi-turn run - the breakpoint after the
profile block (§8.2) hits within a single run's tool loop, before a second day ever
arrives to benefit from cross-run caching. `usage.cache_read_tokens` is asserted nonzero
in the run record; a regression there is visible immediately rather than showing up as a
surprise bill at the end of the month.

At daily cadence, `high` effort lands at roughly **$15-36/month** for this network's
volume; `medium` roughly **$15-17/month**. Both are well inside the original $12-45/month
projection. Your own volume will differ - a much larger firewall log or DNS query volume
raises the evidence-bundle and tool-result token counts proportionally.

Levers, all env vars, in the order worth reaching for:
1. `DAWNPATROL_AI_EFFORT` — `medium` for routine days.
2. `DAWNPATROL_AI_MAX_TOOL_CALLS` — caps loop length.
3. `DAWNPATROL_AI_TASK_BUDGET_TOKENS` — the model paces itself.
4. `DAWNPATROL_AI_MAX_COST_USD` — hard abort; the run still produces a
   deterministic-only report rather than nothing.
5. `DAWNPATROL_AI_MODEL` — Sonnet 5 or Haiku 4.5.

A run that trips the cost ceiling degrades to "analyzer signals rendered without agent
narrative", flagged in the data-quality section. It never produces no report at all.

---

## 9. Guardrails and self-validation

### 9.1 Guardrails enforced in code

`adjudicate.py` runs after the agent and before rendering. Every rule that the current
prompt states as an instruction becomes a validator:

| Rule | Enforcement |
|---|---|
| A finding must trace to real data | `signal_ids` non-empty and all resolvable; else rejected |
| Reputation alone never creates a finding | `evidence_kinds == {"reputation"}` → rejected |
| Reputation moves severity by at most one level | clamp against `Signal.severity_hint`; log the clamp |
| Reputation never produces CRITICAL | CRITICAL requires a signal with `local_behavior` evidence |
| Country is never a severity input | lint: country-code token in `why` without other justification → warn into data-quality |
| Overall status rollup | computed: RED if any CRITICAL or ≥2 HIGH; AMBER if any HIGH or ≥3 MEDIUM; else GREEN |
| No credential ever appears in output | secret-scan the rendered body against all configured secret values; abort delivery on hit |
| Report is 7-bit ASCII, ≤72 cols (plaintext renderer) | renderer guarantees it; unit test asserts it |
| Failed vs. suspect source language | renderer selects wording from the health enum |
| Suppressed findings stay suppressed | matched against `suppressions`; moved to an appendix line, never silently dropped |

Clamps and rejections are recorded in the run record and surfaced in the data-quality
section, so you can see when the model tried to over-reach. That is useful signal about
whether the prompt needs tuning.

**Suppression** gets its own mechanism because its absence is how these systems die. When
a finding turns out to be benign-but-weird, `dawnpatrol suppress <finding_id> --reason
"..." --days 90` writes a matcher to `state.db`. Future matching findings move to a
one-line "suppressed" appendix rather than being deleted — so a tuned-out pattern that
changes character is still visible — and every suppression carries an expiry that forces
periodic re-examination. Without this, the same false positive appears every morning
until you stop reading the report, which is a worse outcome than missing it.

### 9.2 Self-validation (canaries)

A pipeline that reports GREEN for 200 consecutive days is indistinguishable from a
pipeline that is silently broken, and both the model and the reader will stop paying
attention. `canary.py` closes that loop.

Before collection, the canary module injects synthetic signals whose detection is
deterministic and verifiable — a resolution of a domain placed on a local denylist for
exactly this purpose, a synthetic beacon cadence, a burst that should trip the spike
detector. After adjudication, it asserts each one was surfaced.

```python
class Canary(ABC):
    name: str
    def inject(self, ctx: RunContext) -> CanaryToken: ...
    def assert_detected(self, report: Report, token: CanaryToken) -> CanaryResult: ...
```

The result goes in the report header, not buried in section 10:

```
Detection self-test        : 3/3 canaries detected
```

A failed canary is itself a CRITICAL finding: the pipeline is not detecting things it is
definitionally supposed to detect, which means every GREEN since the last successful
canary is suspect. Canaries run on a configurable subset of runs
(`DAWNPATROL_CANARY_EVERY_N_RUNS`, default 1) since they cost almost nothing.

This is the difference between a report that says GREEN and a report that says GREEN and
demonstrates it was actually looking.

See `docs/components/canaries.md` for the full contract, how canary events stay isolated
from real statistics, and a worked example of adding a new canary.

---

## 10. Configuration

**Secrets and runtime knobs: environment variables.** Every one supports a `_FILE`
suffix (`DAWNPATROL_SOURCE_LIBRENMS_TOKEN_FILE=/run/secrets/librenms`) for Docker secrets.

```bash
# Schedule
DAWNPATROL_SCHEDULE="0 6 * * *"        # cron; empty = run once and exit
DAWNPATROL_TZ="UTC"
DAWNPATROL_RUN_ON_START=true
DAWNPATROL_WINDOW_HOURS=48

# Paths
DAWNPATROL_DATA_DIR=/var/lib/dawnpatrol
DAWNPATROL_OUTPUT_DIR=/out
DAWNPATROL_PROFILE=/etc/dawnpatrol/profile.yml

# AI
ANTHROPIC_API_KEY=...
DAWNPATROL_AI_MODEL=claude-opus-5
DAWNPATROL_AI_EFFORT=high
DAWNPATROL_AI_MAX_COST_USD=3.00
DAWNPATROL_AI_MAX_TOOL_CALLS=25

# Sources — presence of required vars auto-enables the plugin
DAWNPATROL_SOURCE_LIBRENMS_URL=http://librenms.example/api/v0
DAWNPATROL_SOURCE_LIBRENMS_TOKEN=...
DAWNPATROL_SOURCE_LIBRENMS_DEVICES=3,4,7
DAWNPATROL_SOURCE_PIHOLE_URL=http://pihole.example/api
DAWNPATROL_SOURCE_PIHOLE_PASSWORD=...

# Enrichment
DAWNPATROL_ENRICH_ABUSEIPDB_KEY=...
DAWNPATROL_ENRICH_ABUSEIPDB_BUDGET=25
DAWNPATROL_ENRICH_ISMALICIOUS_KEY=...

# Outputs
DAWNPATROL_OUTPUT_SMTP_HOST=...
DAWNPATROL_OUTPUT_SMTP_TO=...
DAWNPATROL_OUTPUT_WEBHOOK_URL=...
DAWNPATROL_OUTPUT_WEBHOOK_RUN_WHEN=AMBER,RED
```

**Network topology: a mounted YAML profile.** This is everything that is true about *your*
network and must not be in a public repo. It is data the agent reads, not code.

```yaml
site: { name: "home", timezone: "UTC" }

zones:
  - name: lan
    cidrs: ["192.168.1.0/24"]
    trust: trusted
  - name: iot
    cidrs: ["192.168.50.0/24"]
    trust: untrusted
    gateway: "192.168.1.8"
    notes: "Cameras and home automation. Unpatchable and chatty. Highest-risk
            segment. Expected egress: a small stable set of vendor cloud
            endpoints plus NTP. Anything else is notable."
    expected_egress_domains: ["*.vendor-cloud.example", "*.pool.ntp.org"]
  - name: dmz
    cidrs: ["192.168.15.0/24"]
    trust: semi-trusted
    gateway: "192.168.1.2"
    notes: "Windows Server reached via TeamViewer. Inbound RDP/SMB reaching this
            host is HIGH. Unexpected outbound is HIGH."
    expected_egress_domains: ["*.teamviewer.com", "*.microsoft.com"]

hosts:
  - { ip: "192.168.1.1",  role: "router/firewall/vpn", model: "Example RT-1234" }
  - { ip: "192.168.1.53", role: "dns-resolver", authoritative_resolver: true }
  - { ip: "192.168.1.55", role: "monitoring" }

policy:
  wan_ip_is_dynamic: true            # a WAN IP change is not an incident
  approved_resolvers: ["192.168.1.53"]
  attack_surface_ports: [22, 23, 80, 443, 445, 1194, 3306, 3389, 5060,
                         5432, 5900, 8080, 8443, 8728]
  nat_attribution_limited_behind: ["192.168.1.8", "192.168.1.2"]

known_quirks:
  - "Some consumer router firmware mislabels routine roaming/watchdog chatter
     as 'emerg' severity. Break emerg counts down by program before concluding."
  - "One IoT client emits malformed DNS-SD names with non-UTF-8 bytes.
     Client-side quirk, not a security finding."
```

`nat_attribution_limited_behind` is how the attribution-limit caveat stops being a prompt
rule: the renderer emits the "originating from behind the IoT gateway; per-device
attribution requires OpenWRT-side logging" language automatically for any finding whose
subject is one of those gateways.

`known_quirks` gives you a place to record environment truths without editing a prompt —
the entries are injected into the cached profile block.

See `docs/components/profile.md` for every field's effect on analysis in detail, and a
worked example of documenting a new segment.

---

## 11. Container and scheduling

**Scheduling is in-process**, `croniter` plus a sleep loop, rather than cron or
supercronic. One process, PID 1 is the app, logs go to stdout unmodified, signal handling
and graceful shutdown are straightforward, and the schedule is a plain env var. Running
`DAWNPATROL_SCHEDULE=""` executes one run and exits, which is exactly what you want for
testing and for driving it from an external scheduler instead.

```dockerfile
FROM python:3.12-slim
RUN useradd -r -u 10001 dawnpatrol
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY dawnpatrol/ ./dawnpatrol/
USER dawnpatrol
VOLUME ["/var/lib/dawnpatrol", "/out"]
HEALTHCHECK --interval=5m CMD python -m dawnpatrol.cli healthcheck
ENTRYPOINT ["python", "-m", "dawnpatrol.cli"]
CMD ["serve"]
```

Single stage, slim base, non-root, no build toolchain in the final image. `healthcheck`
reads a heartbeat file the scheduler touches, so a wedged scheduler is visible to Docker.

CLI surface:

```
dawnpatrol serve                       # scheduler loop (default)
dawnpatrol run                         # one full run now
dawnpatrol run --stop-after analyze    # no API spend; dumps the evidence bundle
dawnpatrol run --dry-run               # everything except delivery
dawnpatrol run --from-run <id>         # re-analyze stored events, no re-collection
dawnpatrol probe                       # connectivity + auth check on every source
dawnpatrol list-plugins                # what was discovered and whether it is enabled
dawnpatrol validate                    # config and profile validation
dawnpatrol canary --check              # run the detection self-test standalone
dawnpatrol suppress <id> --days 90     # tune out a false positive, with an expiry
dawnpatrol hunt --domain x --days 180  # retrospective IOC search over the long-term store
dawnpatrol render <run_id> --format md # re-render a stored report
```

`--from-run` matters for iteration: you can develop analyzers and prompt changes against
a real captured day without re-pulling 300k records or hammering the APIs.

---

## 12. External agent access (MCP)

Everything above describes one closed loop: collect, reduce, judge, report, deliver,
once a day. That loop produces a good morning briefing. It is a poor fit for the moment
a briefing says something worth digging into, because digging in means re-running
collection with different parameters, writing ad hoc SQL against events the pipeline
already has, or re-reading the network profile to check a hunch — none of which should
require SSHing into the box or re-deriving context a second AI system already built.

`dawnpatrol/mcpserver/` answers that with a second, optional interface onto the same
capabilities: an MCP (Model Context Protocol) server, reachable over streamable HTTP,
that an external agent — a human's own Claude session, an incident-response bot, a
SIEM's enrichment step — can call directly. It is not a new capability surface. Every
tool it exposes is a thin wrapper over something stages 1-10 already do:

| Tool | Wraps |
|---|---|
| `list_reports`, `get_latest_report`, `get_report` | The files `outputs/file_report.py` already writes |
| `describe_event_schema`, `query_events` | The identical `agent/sqlguard.py` validator the in-run investigation agent's SQL tool uses |
| `get_metric_history` | `Store.metric_history` |
| `get_network_profile` | `Profile.as_context()` — the same text block cached into the harness system prompt |
| `list_source_plugins` | `registry.discover` + `env_satisfied`, the same introspection `list-plugins` uses |
| `trigger_analysis` | `Runner.run()` — the identical pipeline a scheduled run executes |

Two design decisions carry the actual safety weight:

**It is one door onto existing rooms, not a new room.** `trigger_analysis` cannot make
the pipeline do anything `dawnpatrol run` at a terminal could not already do, and
`query_events` cannot reach a table or bypass a rule `agent/sqlguard.py` does not already
enforce for the investigation agent itself. Auditing the MCP surface is auditing whether
the wrapping is thin, not auditing a second implementation of read access.

**It is the one thing in this design that listens, so it defaults to off and to
authenticated.** `DAWNPATROL_MCP_ENABLED` must be set explicitly. Every request requires
`Authorization: Bearer <token>`, checked with a constant-time comparison
(`hmac.compare_digest`) in a small ASGI middleware (`mcpserver/auth.py`) wrapped *around*
the MCP app rather than implemented inside it — deliberately independent of whatever
authentication semantics a future `mcp` SDK major version changes. The token is either
`DAWNPATROL_MCP_TOKEN` (operator-supplied, stable across restarts) or generated fresh at
startup and logged exactly once, since a generated token that is never displayed again is
useless and a generated token that is displayed on every log line is a leak waiting to be
scraped.

**Concurrency is a real, shared lock, not a convention.** `trigger_analysis` and the
scheduled cron job both go through the same `guarded_run` closure built in
`cli.cmd_serve`, wrapping a single `threading.Lock`. Two runs writing to `run.db`
simultaneously is not a scenario worth supporting; a triggered run that arrives mid-cron
gets a clean `"a run is already in progress"` response instead of silent corruption or a
long hang.

**`trigger_analysis` never emails**, structurally: it calls `Runner.run(skip_outputs=
frozenset({"smtp"}))`, which drops the `smtp` output from the delivery list before stage
10 runs at all — the same code path other outputs use, not a special case bolted onto the
SMTP plugin. File output still happens, so the result is retrievable afterward through
`get_report` exactly like a scheduled run's.

**The agent notebook is a second, narrower door, gated separately.** Every tool above is
read-only except `trigger_analysis`, and even that only runs the existing pipeline - it
doesn't change what a *future* run believes. `add_notebook_entry` does: text an external
agent submits is stored in a new `notebook` table (`schema.py`) and read back by
`agent/harness.py`, appended to `system_context` immediately after
`profile.as_context()` - alongside the network documentation, never in place of it. That
is a materially different trust boundary (shaping future judgment, not just reading data
or spending API budget), so it does not turn on with `DAWNPATROL_MCP_ENABLED` - it needs
its own `DAWNPATROL_MCP_NOTEBOOK_ENABLED`, off by default even when the rest of the MCP
surface is on. Two bounds keep it from becoming an unbounded cost or context-injection
surface: `DAWNPATROL_MCP_NOTEBOOK_MAX_ENTRY_CHARS` rejects an over-long single note
outright, and `DAWNPATROL_MCP_NOTEBOOK_MAX_INJECTED` caps injection to the most recent N
entries even though the full history stays readable via `read_notebook`. A note still
cannot fabricate a finding - `adjudicate.py`'s `signal_ids` requirement applies uniformly
regardless of what the model was told in its system prompt. `delete_notebook_entry`
removes one permanently by id - immediate, no expiry mechanism, no soft-archive - since a
note is context an agent retracts when it's stale or wrong, not a tuning rule that needs
its own audit trail the way a suppression does.

See `docs/components/mcp-server.md` for the tool reference, the notebook's full design
rationale, deployment guidance, and a worked example of adding a new tool.

---

## 13. Security

This is security tooling that reads attacker-influenced data and will be published, so:

**Untrusted content handling.** Domain names, hostnames, ISP strings, and log messages are
attacker-influenced. They are never interpolated into the system prompt. They arrive only
inside tool results and the evidence bundle, inside clearly delimited blocks, with a
standing instruction that content within them is data. More importantly, the structural
defenses do the real work: the model has no shell, no fetch, no filesystem, and no
delivery tool, so there is no action for injected text to trigger. Delivery recipients
come from env vars and cannot be influenced by run content.

**Secret hygiene.** Secrets only from env / `_FILE`. A `SecretStr` wrapper keeps them out
of reprs and logs. Before any output plugin runs, the rendered body is scanned for every
configured secret value; a hit aborts delivery loudly. `.env.example` ships with
placeholders only, and `docs/oldagentfiles/` is gitignored because it contains live
tokens.

**Immediate action item:** the tokens in `docs/oldagentfiles/` — the LibreNMS token, the
Pi-hole password, and the ismalicious API key — are now in a gitignored directory and
were never committed, but they have existed in plaintext in an Open-WebUI skill store.
Rotate all three before this repo goes public.

**SQL tool.** Read-only URI connection, single statement, `LIMIT` injected, statement
timeout, result byte cap, and `run.db` opened separately from `state.db` so the agent
cannot read the deliveries or config tables.

**Egress.** The container talks to your monitoring hosts, the two reputation APIs, the
Anthropic API, and your SMTP/webhook destination. All configurable; documented so it can
be firewalled to an allowlist.

---

## 14. Testing

220 tests, `pytest -q`, fully offline - no network, no API key, no spend - and that
includes an end-to-end pipeline exercise against a stubbed provider. CI
(`.github/workflows/ci.yml`) runs the same suite plus `ruff` on every push and pull
request, across Python 3.11-3.13.

- **Source parsers**, covering the failure modes the original agent skills documented -
  the epoch-vs-string timestamp trap, cursor-pagination duplication, the 0xc0 poison
  record, truncated pagination - each as a dedicated test (`tests/test_sources.py`). They
  are built as synthetic records constructed inline rather than recorded API fixtures on
  disk: `tests/fixtures/` exists as the on-ramp for that if a future contributor wants to
  add real (scrubbed) captures, but inline construction already gives every trap a
  deterministic regression test without the risk of a "scrubbed" fixture someday turning
  out not to be.
- **Analyzers** against synthetic event sets with known-correct expected signals: a
  textbook persistent prober, a /24 sweep, conntrack return traffic, a stepped-TTL probe,
  a DGA burst.
- **Renderers** - property tests asserting 7-bit ASCII, no line over 72 columns, all ten
  sections present in order, no unsubstituted tokens, every empty section carrying its
  documented empty-state line - plus, for the HTML renderer, that attacker-influenced
  finding text is escaped rather than passed through as markup.
- **Adjudication** - each guardrail gets a test feeding it a deliberately non-compliant
  agent response and asserting the clamp or rejection.
- **The MCP surface** (`tests/test_mcpserver.py`) - every tool's logic against a real
  temp-directory `Store`, plus the bearer-auth middleware against a raw ASGI scope, with
  no real HTTP server started.
- **End-to-end** with a stubbed model returning a canned `Analysis`, so the full pipeline
  is exercised with zero API spend.

---

## 15. Phasing

Every phase below is complete except the two gaps called out explicitly. Nothing here is
aspirational; each row names the actual files that satisfy it.

| Phase | Scope | Status |
|---|---|---|
| 1 | Core models, registry, config, store, CLI, `librenms_syslog` + `pihole_dns` sources, `file_report` output, Dockerfile | **Done.** `dawnpatrol run --stop-after analyze` produces a verified event store from a real network - exercised against a real deployment, not just fixtures. |
| 2 | Analyzers: volume, patterns, DNS anomalies, segments, correlation, baseline delta | **Done.** All seven ship (`dawnpatrol/analyzers/`); zero API spend at this stage. |
| 3 | Agent harness, tools, structured output, adjudication, plaintext renderer, SMTP output | **Done.** Validated against a live network with a real model: real findings, real adjudication, real email delivery. |
| 3.5 | Canary self-validation, suppression, long-term IOC store and `hunt` | **Done.** Both canaries fire in production; a canary excluded by an ad hoc source restriction was observed correctly reporting NOT DETECTED and escalating status, rather than passing silently. |
| 4 | Enrichment plugins, caching, budgets; webhook output; markdown/html renderers | **Mostly done.** `abuseipdb.py` and `ismalicious.py` ship with caching and budget enforcement (`enrichment/broker.py`) but are unexercised against live traffic in this deployment - no reputation API keys configured yet. `webhook.py` and `markdown.py`/`html.py` all ship. |
| 4.5 | MCP server: read-only tools plus `trigger_analysis`, bearer auth, shared run lock | **Done.** Deployed and verified end to end: authentication (accept/reject), all nine tools, the shared-lock rejection of a concurrent trigger, and a real `trigger_analysis` call that surfaced a genuine canary failure and RED status. |
| 5 | Scheduler hardening, healthcheck, docs, fixtures, CI, public release prep | **Mostly done.** Healthcheck, `docs/components/*.md`, and CI (`.github/workflows/ci.yml`) all ship. `tests/fixtures/` remains an empty on-ramp - the traps it was meant to guard against are covered by inline synthetic fixtures instead (§14) - and the repo has not yet been pushed to a public remote. |

The two remaining gaps (live enrichment-key testing, on-disk recorded fixtures) are
both additive: neither blocks anything else in this list, and both are one small,
well-scoped task away from closing - the first needs an operator to supply a key, the
second needs someone to decide the inline-synthetic-fixture tradeoff above is worth
revisiting.

---

## 16. Design decisions

Design questions the first draft of this document posed as open. Each is resolved by
what actually shipped; the reasoning is kept here because the "why" outlives the code
that embodies it.

1. **Window strategy: per-source native windows, reconciled through `state.db`.**
   Firewall and DNS keep their own retention-driven windows (48h / ~24h) rather than
   being clamped to a shared one; `Source.max_window_hours` records the ceiling and the
   renderer labels each source's actual achieved coverage rather than implying a
   uniform window. Trend comparison happens through `Baseline`/`state.db`, not through
   forcing every source onto the same clock.

2. **Raw event retention: 7 days, configurable.** `DAWNPATROL_RETENTION_RAW_DAYS`
   defaults to 7 (a few hundred MB), giving `run --from-run` multi-day drill-down
   without real cost. The long-term IOC slice (`ioc_dns`/`ioc_flow`) is the answer for
   anything past that: 180 days by default, a few bytes per row.

3. **SQL tool scope: read-only SQL, not a fixed query API.** Shipped as designed
   (`agent/sqlguard.py`): the safety is structural (single `SELECT`, allowlisted
   tables, injected `LIMIT`, a read-only connection) rather than behavioral, so the
   capability is real and the risk is bounded regardless of what the model tries. The
   same validator now backs both the in-run investigation agent's tool and the MCP
   server's `query_events` (§12) - one implementation, two callers.

4. **Delivery on GREEN: `ALWAYS` by default, per-output override.** Email defaults to
   daily; a dead-man's-switch ping (`healthchecks_ping`) remains a reasonable future
   output but was not necessary to ship the core loop - `run_when` already makes silence
   vs. noise a config decision per destination, not a code one.

5. **Model default: `claude-opus-5`.** Kept, and validated against real cost data rather
   than an estimate: a full run against this network (~28k firewall records, ~140k DNS
   queries) costs $0.50-$1.00 depending on `DAWNPATROL_AI_EFFORT`, comfortably inside the
   $12-45/month range projected in §8.5. The reduction layer is what makes Opus
   affordable; `claude-sonnet-5` and `claude-haiku-4-5` remain one env var away for a
   quieter network or a tighter budget.

### Extending source coverage

Which telemetry DawnPatrol consumes was deliberately left open at design time, and stays
open by construction. The current build ships two sources (`librenms_syslog`,
`pihole_dns`); `EventKind` already reserves `IDS` and `FLOW` for a future intrusion-
detection or NetFlow source.

This is the payoff of the plugin design, not a gap in it: adding a source is one file
implementing `collect()` and `self_test()` (see `docs/components/sources.md`), and every
analyzer, enrichment path, renderer, and output downstream - plus the MCP server's
`list_source_plugins`/`trigger_analysis` - picks it up without modification.
