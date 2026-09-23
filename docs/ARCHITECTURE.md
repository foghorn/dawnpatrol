# DawnPatrol Architecture

A single-container, scheduled threat-hunting pipeline. Deterministic code does the
collection, normalization, and statistics; an AI agent does the judgment. Everything
environment-specific — addresses, hostnames, credentials, topology — lives in
configuration, never in source, so the codebase itself is safe to publish.

This document describes the system as it is built, for a reader (human or AI) trying to
understand how it actually works. For a tutorial-style walkthrough of any one plugin
type, with a worked example of building your own, see `docs/components/` — this document
is the systems-level view of how the pieces fit together.

Three things it is not: a real-time IDS (it's a scheduled batch analyst — collection runs
on a schedule, not a stream); a SIEM (it reads your existing telemetry, it doesn't
replace it); or multi-tenant (one deployment watches one network — run a second container
for a second network).

---

## 1. Repository map

```
dawnpatrol/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── .env.example
├── README.md
├── config/
│   └── profile.yml                 # network topology — gitignored, real values live here
├── dawnpatrol/
│   ├── cli.py                      # argparse entry point: serve/run/validate/... (§10)
│   ├── scheduler.py                # in-process cron loop + heartbeat file
│   ├── config.py                   # env -> typed Settings (§9)
│   ├── context.py                  # RunContext: threaded through every stage
│   ├── profile.py                  # profile.yml -> Profile (zones, hosts, policy)
│   ├── registry.py                 # plugin discovery, shared by all five plugin kinds
│   ├── models.py                   # Event, Metric, Signal, Finding, Report, ...
│   ├── schema.py                   # SQLAlchemy Table definitions — the one database
│   ├── store.py                    # all reads/writes against that database
│   ├── query.py                    # EventQuery: the typed read API analyzers use
│   ├── devices.py                  # per-run, cross-source device directory
│   ├── verify.py                   # source health classification (OK/DEGRADED/SUSPECT/FAILED)
│   ├── adjudicate.py                # guardrail enforcement, status rollup (§7)
│   ├── budget.py                   # token / dollar / tool-call ceiling
│   ├── canary.py                   # detection self-test (§8)
│   ├── errors.py                   # exception hierarchy, one type per failure mode
│   ├── secrets.py                  # SecretStr, env/_FILE reading, leak scanning
│   ├── runner.py                   # pipeline orchestration — Runner.run(), all 11 stages
│   ├── agent/
│   │   ├── harness.py              # drives one provider through one investigation
│   │   ├── tools.py                # ToolBox: the in-run agent's tool surface
│   │   ├── bundle.py                # evidence bundle assembly (what the model sees)
│   │   ├── schema.py               # JSON schema for the submit_analysis tool
│   │   ├── sqlguard.py             # validates the agent's read-only SQL
│   │   └── prompts/
│   │       ├── system.md
│   │       └── task.md
│   ├── render/
│   │   ├── plaintext.py            # 7-bit ASCII report body — the delivery contract
│   │   ├── markdown.py
│   │   ├── html.py                 # full-page HTML: file output, webhook
│   │   ├── html_email.py           # inline-styled HTML: the email body
│   │   └── json_report.py
│   ├── sources/                    # ── PLUGIN FOLDER (discovered, §5.1) ──
│   │   ├── librenms_syslog.py
│   │   ├── pihole_dns.py
│   │   └── TEMPLATE.py
│   ├── analyzers/                  # ── PLUGIN FOLDER (discovered, §5.2) ──
│   │   ├── firewall_volume.py
│   │   ├── firewall_patterns.py
│   │   ├── dns_anomalies.py
│   │   ├── novel_clients.py
│   │   ├── beaconing.py
│   │   ├── auth_activity.py
│   │   ├── segment_review.py
│   │   ├── data_volume.py
│   │   ├── correlation.py
│   │   ├── baseline_delta.py
│   │   ├── baseline.py             # not a plugin — the Baseline helper every analyzer takes
│   │   └── TEMPLATE.py
│   ├── enrichment/                 # ── PLUGIN FOLDER (discovered, §5.3) ──
│   │   ├── abuseipdb.py
│   │   ├── ismalicious.py
│   │   ├── broker.py               # not a plugin — cache/budget/prefilter enforcement
│   │   └── TEMPLATE.py
│   ├── outputs/                    # ── PLUGIN FOLDER (discovered, §5.4) ──
│   │   ├── file_report.py
│   │   ├── smtp_email.py
│   │   ├── webhook.py
│   │   └── TEMPLATE.py
│   ├── providers/                  # ── PLUGIN FOLDER (discovered, §5.5) ──
│   │   ├── anthropic_provider.py
│   │   ├── openai_provider.py      # native /v1/responses
│   │   ├── openai_compatible.py    # any /v1/chat/completions server
│   │   └── TEMPLATE.py
│   └── mcpserver/                  # external-agent MCP surface (§12)
│       ├── server.py               # tool registration, bearer-auth middleware
│       ├── tools.py                # ToolContext: the tool implementations
│       └── auth.py
└── tests/                          # 430 tests, offline, zero spend (§14)
```

`canary.py` is deliberately not a discovered plugin folder like the five above — it ships
a fixed pair of canaries (`BUILTIN_CANARIES`), not something meant to grow by dropping in
files. See §8.

---

## 2. Pipeline

Eleven stages, run in `runner.py`'s `Runner.run()`. Stages 1–6 and 8–11 are fully
deterministic; only stage 7 calls a model.

```
  1. PLAN        resolve run window, load profile, open the database, load baseline
  2. COLLECT     run every enabled source plugin concurrently -> raw records
  3. NORMALIZE   sources map their own raw records to the common Event model
  4. VERIFY      per-source integrity gates; classify OK / DEGRADED / SUSPECT / FAILED
  5. PERSIST     write events to the database; update the entity baseline
  6. ANALYZE     run every applicable analyzer plugin -> Metrics + Signals
  7. INVESTIGATE agent loop: evidence bundle in, structured analysis out
  8. ADJUDICATE  validate findings, enforce guardrails, compute overall status
  9. RENDER      Report -> plaintext / markdown / html / html_email / json
 10. DELIVER     run every enabled output plugin; record results
 11. CHECKPOINT  purge aged-out data by retention policy
```

Stages 3 and 4 aren't separate function calls — normalization happens inside each
source's own `collect()`, and `verify.classify()` runs once per source right after
collection. `--stop-after analyze` is a first-class CLI mode: it runs stages 1–6, costs
zero API spend, and dumps the exact evidence bundle a model would see — the fast loop for
developing an analyzer (§10).

**Why there's a fourth plugin kind beyond sources, outputs, and reputation lookups.** A
day of firewall and DNS traffic on a real home network is 500,000+ events. That doesn't
fit in a prompt, and paying a model to compute `Counter(ports).most_common(15)` is exactly
the kind of waste this design avoids. Analyzers are the reduction layer that turns
hundreds of thousands of events into a few dozen pre-computed signals and metrics —
dense, numeric evidence a model can actually reason over. It's also the right extension
point for new detection logic: a new heuristic is a new file with one method, testable
against synthetic fixtures, not a paragraph competing for attention in an 80-paragraph
system prompt.

The split in one line: **sources fetch, analyzers count, the agent decides.**

---

## 3. Data model

One flat `Event` type (`dawnpatrol/models.py`), not a per-source shape. This is the
decision that makes cross-source correlation possible at all — a firewall event and a DNS
event have to agree on what `src_ip` means before anything downstream can join them.

```python
class EventKind(StrEnum):
    FIREWALL = "firewall"; DNS = "dns"; SYSTEM = "system"
    AUTH = "auth"; IDS = "ids"; FLOW = "flow"; HTTP = "http"; OTHER = "other"

@dataclass(frozen=True, slots=True)
class Event:
    ts: datetime                  # UTC, tz-aware, required
    source: str                   # plugin name
    kind: EventKind
    dedup_key: str                # stable per-source id — makes re-collection idempotent

    # network (firewall / flow)
    src_ip: str | None = None;    dst_ip: str | None = None
    src_port: int | None = None;  dst_port: int | None = None
    proto: str | None = None      # normalized: tcp/udp/icmp/igmp/...
    action: str | None = None     # drop/accept/reject/allow/block
    iface_in: str | None = None;  iface_out: str | None = None
    ttl: int | None = None;       pkt_len: int | None = None

    # dns
    domain: str | None = None;    qtype: str | None = None
    blocked: bool | None = None;  block_reason: str | None = None
    upstream: str | None = None;  client_ip: str | None = None

    # host / system
    device: str | None = None;    program: str | None = None
    severity: str | None = None;  message: str | None = None
    user: str | None = None

    # derived at normalize time from profile.yml
    src_zone: str | None = None;  dst_zone: str | None = None

    raw: dict = field(default_factory=dict)   # kept in the DB, never bulk-sent to the model
```

`src_zone`/`dst_zone` are assigned by matching IPs against `profile.yml`'s zones — that's
what lets an analyzer say "IoT → external on a non-vendor port" without hardcoding a CIDR
anywhere in the source tree. `Event.device` is not a hostname field for every source — for
`librenms_syslog` it holds LibreNMS's numeric `device_id`, not a name.

Downstream types, in the order data flows through them:

```python
class Metric:                     # deterministic; goes straight into the report
    key: str                      # "fw.drops.total", "dns.block_rate"
    value: float | int | str
    section: str                  # which report section it belongs to
    prior: float | None = None    # filled in from the baseline
    # delta_pct is computed on demand from value and prior

class Signal:                     # a candidate finding, computed deterministically
    id: str                       # stable slug: "fw.prober.203.0.113.45.22"
    analyzer: str
    title: str
    taxonomy: str                 # "scan.persistent_prober", "dns.dga_suspect"
    entities: list[Entity]        # typed subjects: ip / domain / host / port / device / user
    severity_hint: Severity       # a deterministic prior; the agent may adjust it by one level
    confidence: float             # 0-1
    evidence: dict                # numbers and quoted samples only
    support: list[str] = []       # event dedup_keys, for sample_events drill-down
    is_canary: bool = False       # excluded from the bundle and the report if true

class Finding:                    # produced by the agent, validated by adjudicate.py
    id: str; title: str; severity: Severity; confidence: Confidence
    zone: str; taxonomy: str
    what: str; why: str; not_this: str; action: str
    signal_ids: list[str]         # REQUIRED — must resolve to at least one real Signal
    evidence_kinds: list[str]     # {"local_behavior", "reputation", "baseline_delta", ...}
    entities: list[Entity]
    enrichment: list[EnrichmentRef]

class Report:                     # everything the renderers need, fully assembled
    run_id: str; status: Status; findings: list[Finding]; suppressed_findings: list[Finding]
    metrics: list[Metric]; signals: list[Signal]; health: list[SourceHealth]
    devices: list[dict]; executive_summary: str; section_narratives: dict
    trend_notes: list[TrendNote]; actions: list[Action]; data_quality: list[str]
    canaries: list[CanaryResult]; usage: TokenUsage; degraded: bool
```

`Finding.signal_ids` being required and validated is the structural anti-hallucination
measure: a finding that doesn't trace to at least one deterministically-computed signal is
rejected by `adjudicate.py`, not merely discouraged by a prompt rule (§7).

---

## 4. Persistence

One database — SQLite by default, MySQL when `DAWNPATROL_DB_HOST`/`DAWNPATROL_DB_USER`
are both set (credential-driven, not a mode flag, so pointing at a shared database is
purely additive configuration). Every table lives in `schema.py`'s single `MetaData`;
there is no separate per-run database file.

| Table | Scope | Purpose |
|---|---|---|
| `runs` | one row per run | run_id, window, status, per-stage timings, token/cost accounting |
| `source_health` | per run | per-source counts, span, health state, probe results |
| `events` | per run | one row per normalized observation — the raw data itself |
| `metrics` | per run | every deterministic statistic a run produced |
| `signals` | per run | every candidate finding an analyzer computed |
| `findings` | per run | every finding the agent's output survived adjudication as |
| `canaries` | per run | per-run synthetic-signal injections and whether each was detected |
| `deliveries` | per run | per-output success/failure, for "was the report actually sent" |
| `ioc_dns` | per run, day-bucketed | thin `(day, client_ip, domain, queries, blocked)` rows |
| `ioc_flow` | per run, day-bucketed | thin `(day, src_ip, dst_ip, dst_port, proto, hits)` rows |
| `entities` | rolling, not run-scoped | first_seen / last_seen / occurrence counts per `(etype, value)` |
| `enrichment_cache` | rolling, not run-scoped | `(enricher, subject)` -> normalized verdict + TTL |
| `watchlist` | rolling, not run-scoped | items the agent carries forward, with an expiry |
| `suppressions` | rolling, not run-scoped | tuned-out patterns: matcher, reason, author, expiry |
| `notebook` | rolling, not run-scoped | free-text agent notes, off by default (§12) |

Two different lifetimes share this one database. `events` — the bulk of the volume, ~150k
rows per day of raw traffic on a real deployment — is retained for
`DAWNPATROL_RETENTION_RAW_DAYS` (default 7), which still gives multi-day drill-down
without real storage cost. `ioc_dns`/`ioc_flow` are a deliberately narrow slice (a few
bytes per row, no message payload) kept for `DAWNPATROL_RETENTION_IOC_DAYS` (default 180)
specifically so retrospective hunting works: when an IOC surfaces next month,
`dawnpatrol hunt --domain evil.example --days 180` answers whether anything here ever
touched it. `metrics` ages out on its own, longer clock
(`DAWNPATROL_RETENTION_METRICS_DAYS`, default 730 — two years of trend history).

**Everything else in the table above — `signals`, `findings`, `source_health`,
`canaries`, `deliveries`, the `runs` row itself, and the rolling tables — has no
automatic age-based purge at all.** `Store.purge()` (run at CHECKPOINT, stage 11) only
touches `events` (by run age), `ioc_dns`/`ioc_flow` (by day), `metrics` (by timestamp),
`enrichment_cache` (by expiry), and expired `watchlist` rows. That's a deliberate choice —
finding history is what makes trend language honest ("RECURRING, day 4" is a database
count, not a recollection) — but it means a database left running indefinitely
accumulates those tables forever unless something else removes rows. `dawnpatrol
delete-run <run_id>` and `dawnpatrol run --ephemeral` (§10) are the on-demand answer:
each deletes every row a specific run owns across all nine run-scoped tables, plus that
run's report files, immediately rather than waiting on age.

**`entities` is the one table neither mechanism can clean up after.** It has no
`run_id` — it's a rolling `(etype, value) -> first_seen, last_seen, occurrences` map, and
PERSIST (stage 5) updates it from a run's own events *before* that run's own ANALYZE
stage (stage 6) even builds a `Baseline` and reads it back. A run's contribution to those
counts is folded in immediately and can't be surgically subtracted out afterward — the
same reason `Store.purge()` never touches it either. This is what makes novel-IP and
novel-domain detection deterministic (`Baseline.novel()` is a real query, not a diff
against a note a model wrote yesterday), but it also means a test run leaves a small,
permanent trace there even when `--ephemeral` cleans up everything else.

The agent's own read-only SQL tool (`agent/sqlguard.py`, §6.3) can reach exactly six of
these tables — `AGENT_READABLE = {"events", "metrics", "signals", "ioc_dns", "ioc_flow",
"entities"}` — everything else (deliveries, config-adjacent tables, the notebook) is out
of reach regardless of what SQL the model writes.

---

## 5. Plugin architecture

Five plugin folders — sources, analyzers, enrichment, outputs, providers — share one
discovery mechanism (`registry.py`): import every module in the package (skipping
`TEMPLATE.py`, `base.py`, and anything starting with `_`), collect concrete subclasses of
the folder's base class, key them by their declared `name`. A plugin with a duplicate
`name` is a hard error at discovery time, not a silent overwrite.

```python
def discover(package: ModuleType, base: type[T]) -> list[type[T]]:
    load_modules(package)                       # import every module; one bad plugin logs, doesn't crash the run
    return _concrete_subclasses(base, package.__name__)   # scoped to this package only
```

**Enablement is automatic and env-driven.** A plugin declares the environment variables
it needs in `requires_env`; if every one of them (or its `_FILE` twin) is present, the
plugin turns on. No registry file, no `ENABLED_PLUGINS` list to maintain.
`DAWNPATROL_DISABLE=pihole_dns` is the escape hatch, and
`DAWNPATROL_SOURCES=librenms_syslog` (or `_ANALYZERS`/`_ENRICHERS`/`_OUTPUTS`) pins an
explicit allowlist when you want determinism. `dawnpatrol list-plugins` shows exactly
what was discovered and, for anything disabled, exactly which variable it's still waiting
on.

### 5.1 Sources

```python
class Source(ABC):
    name: str
    kinds: frozenset[EventKind]
    requires_env: frozenset[str]
    max_window_hours: int | None = None    # hard retention ceiling, e.g. 24 for a DNS log
    min_expected_records: int = 0          # volume floor below which a result looks broken

    def configure(self, profile: Profile) -> None: ...
    @abstractmethod
    def collect(self, window: Window, ctx: RunContext) -> CollectionResult: ...
    def self_test(self, ctx: RunContext) -> list[Probe]: ...
    def extra_health_notes(self, result: CollectionResult) -> list[str]: ...
```

`self_test()` is the differential-probe mechanism: when a source returns zero records,
the framework (`verify.classify()`) automatically calls it before deciding anything, and
the probe results are recorded verbatim on the run. That's what makes "the API returned
zero rows" and "the device stopped forwarding" distinguishable without relying on a model
to remember to check. Health states are deliberately four, not two —
`OK` / `DEGRADED` (partial but usable, e.g. a DNS source whose own retention is shorter
than the requested window) / `SUSPECT` (zero rows, probes inconclusive) /
`FAILED` (zero rows, probes affirmatively confirm an outage). Only affirmative probe
evidence ever justifies `FAILED`; an HTTP 401 is treated as a configuration fault, never
an outage. `SUSPECT` never renders as "monitoring is blind" — the renderer has distinct
language per state, so that false-outage failure mode is structurally impossible, not
just unlikely.

Window handling is per-source: a source declaring `max_window_hours = 24` gets clamped by
the framework (`Window.clamp_hours`), and the clamp is recorded as a known limit rather
than a shortfall — the labels a reader sees are generated from the window each source
actually achieved, not a uniform number every source is forced onto.

Two sources ship: `librenms_syslog.py` (firewall/kernel logs, DHCP leases, dnsmasq query
logs, router-admin logins — everything LibreNMS's syslog collector forwards) and
`pihole_dns.py` (DNS queries and block decisions). `EventKind` already reserves `IDS` and
`FLOW` for a future intrusion-detection or NetFlow source; adding one is one file
implementing `collect()` and `self_test()`, and every analyzer, enrichment path,
renderer, output, and the MCP server's own `list_source_plugins`/`trigger_analysis`
picks it up without modification. See `docs/components/sources.md` for the full
contract and both shipped sources walked through in detail.

### 5.2 Analyzers

```python
class Analyzer(ABC):
    name: str
    requires_kinds: frozenset[EventKind]      # skipped entirely if no source supplied these
    requires_sources: frozenset[str] = frozenset()
    order: int = 100                          # lower runs first

    @abstractmethod
    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        """Pure: no network, no model calls. Must not raise on empty input."""
```

`EventQuery` (`query.py`) is a typed, run_id-scoped read API over the events table —
`q.count(kind=..., action="drop")`, `q.top("dst_port", n=15, by="unique:src_ip")`,
`q.hourly(...)`, `q.dns_domain_stats(...)`, `q.source_profile(...)`, `q.subnet_spread(...)`
and more — so analyzers stay short and readable, and every method is portable across
SQLite and MySQL without an analyzer knowing which dialect it's running against. A query
can also be scoped to exclude or include only specific sources — that's the mechanism
that keeps canary events out of real statistics while still letting a second, isolated
pass verify they were detected (§8).

`Baseline` (`analyzers/baseline.py`) exposes history: `baseline.prior(metric_key)` (last
run's value), `baseline.novel(EntityType.DOMAIN, [...])` (never-seen-before check, with a
one-hour grace window since an entity is written to the baseline during the same run that
first observes it), `baseline.series(key, days=30)`, `baseline.recurrence(taxonomy,
entity_value)`, `baseline.watchlist()`. Newly-seen-domain detection is a real database
query, not a diff against a note.

Ten analyzers ship, run in `order`: `firewall_volume` (10), `firewall_patterns` (20),
`dns_anomalies` (30), `novel_clients` (35), `beaconing` (40), `auth_activity` (45),
`segment_review` (50), `data_volume` (55), `correlation` (60), `baseline_delta` (900, runs
last deliberately, so it can see what every other analyzer produced). See
`docs/components/analyzers.md` for what each one does and the full `EventQuery`/`Baseline`
API, and `docs/components/signals.md` for an exhaustive per-signal catalog — taxonomy,
severity, confidence, exact trigger condition, evidence fields — of everything any
analyzer currently emits.

### 5.3 Enrichment

```python
class Enricher(ABC):
    name: str
    subject_types: frozenset[str]      # {"ip"} / {"domain"} / {"url"} / {"hash"}
    requires_env: frozenset[str]
    default_budget: int = 25           # lookups per run
    cache_ttl: timedelta = timedelta(days=7)
    batch_size: int = 1

    @abstractmethod
    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]: ...
    def prefilter(self, subjects: list[str]) -> list[str]: ...
```

Three things the framework (`enrichment/broker.py`) enforces so no plugin — and no
prompt — has to: **caching** (every lookup cached by `(enricher, subject)` with a TTL;
the same top scanner IPs recur every day, so most lookups after week one are free),
**budget** (enforced at the tool boundary — the (N+1)th call returns a structured
"budget exhausted" result rather than the model being asked not to overspend), and
**prefiltering** (`abuseipdb.py` drops non-routable addresses before spending budget on
them; `ismalicious.py` drops domains `profile.is_benign_domain()` already recognizes).

`Enrichment` is a normalized verdict (`score`, `verdict`, `whitelisted`, `categories`,
`attributes`, `raw`) so an analyzer or the model can consume any enricher without caring
whether it was AbuseIPDB or something added next month. AbuseIPDB's `totalReports` —
heavily inflated for cloud and security-vendor space, and uncorrelated with the actual
abuse score — is deliberately absent from the normalized shape and lives only in `raw`
for audit; the model cannot misreport a number it's never handed. Two enrichers ship:
`abuseipdb.py` and `ismalicious.py`. See `docs/components/enrichment.md` for the full
contract and a worked example of adding a new reputation source.

### 5.4 Outputs

```python
class Output(ABC):
    name: str
    renderer: str = "plaintext"     # "plaintext" | "markdown" | "html" | "html_email" | "json"
    requires_env: frozenset[str]
    default_run_when: frozenset[Status] = {GREEN, AMBER, RED}
    default_important_only: bool = False

    @abstractmethod
    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        """Must not raise; return ok=False instead."""
```

Renderers are shared library code, not plugins — an output picks one by name, so every
new delivery destination inherits a correct report body instead of re-implementing
formatting. `run_when` (`DAWNPATROL_OUTPUT_<NAME>_RUN_WHEN=AMBER,RED` /
`IMPORTANT` / `ALWAYS` / `NEVER`) makes "page me only when something's notable, but
always write the file" a per-destination config setting, not prompt logic.
`Report.has_important()` is what `IMPORTANT` checks against: status other than GREEN, a
failed canary, or an unusable source.

Three outputs ship: `file_report.py` (writes `${OUTPUT_DIR}/YYYY-MM-DD/report-<run_id>.*`
plus a `latest.*` copy of each configured format — always enabled, the durable record of
every run), `smtp_email.py` (a multipart message: `html_email` as the formatted body a
normal client shows, `plaintext` underneath as the fallback; recipients come from
`DAWNPATROL_OUTPUT_SMTP_TO`, never from run content — see §13), and `webhook.py` (generic
JSON POST — ntfy, Slack, Discord, Home Assistant). See `docs/components/outputs.md` for
the full contract and a worked example of a new destination.

### 5.5 Providers

```python
class Provider(ABC):
    name: str
    requires_env: frozenset[str]
    price_input_per_mtok: float = 0.0
    price_output_per_mtok: float = 0.0
    price_cache_read_per_mtok: float = 0.0
    price_cache_write_per_mtok: float = 0.0

    @abstractmethod
    def run_agent(self, *, system_static: str, system_context: str, user_message: str,
                  tools: list[ToolSpec], max_turns: int,
                  on_turn: Callable[[TokenUsage], None] | None = None) -> AgentRun: ...
    def estimate_cost(self, usage: TokenUsage) -> float: ...   # base formula; a provider may override
    def available(self) -> tuple[bool, str]: ...
```

The model backend is a plugin like everything else, discovered the same way. Three ship:
`anthropic_provider.py` (the default), `openai_provider.py` (native `/v1/responses`,
built specifically for reasoning-effort control and correct cache-token accounting on
that endpoint), and `openai_compatible.py` (any `/v1/chat/completions` server — Ollama,
LM Studio, vLLM, or a hosted OpenAI-shaped API; a local model is one environment variable
away, not a code change). `DAWNPATROL_AI_PROVIDER`/`DAWNPATROL_AI_MODEL` select the
combination; nothing else in the pipeline depends on which one is active. See
`docs/components/providers.md` for the contract and a worked example of adding a new
backend, and §6.1 below for what each shipped provider actually does differently.

---

## 6. The AI harness

### 6.1 Model and loop

The default is Claude Opus 5 (`claude-opus-5`) via `anthropic_provider.py`, which drives
a hand-written tool loop rather than the SDK's own tool runner — a deliberate choice: the
harness needs per-turn budget checks, cost accounting mid-loop, and a terminal-tool break,
and keeping the loop's shape identical across providers makes them easy to reason about
side by side. `DAWNPATROL_AI_MODEL` is a plain env var; nothing about the pipeline assumes
a particular model, and `claude-sonnet-5`/`claude-haiku-4-5` are one variable away for a
quieter network or a tighter budget.

Per-turn request configuration (Anthropic): `thinking: {"type": "adaptive"}` (this is
genuinely reasoning-heavy work), `output_config: {"effort": ...}` (`DAWNPATROL_AI_EFFORT`,
default `high` — the primary cost/quality dial), an optional `output_config.task_budget`
when `DAWNPATROL_AI_TASK_BUDGET_TOKENS >= 20000` (gives the model a ceiling to pace
itself against so it wraps up rather than being cut off mid-investigation), and streaming
throughout since `max_tokens` is large. Server-side refusal fallback
(`betas: ["server-side-fallback-2026-07-01"]`, `fallbacks: "default"`) is on by default —
security log content occasionally trips a classifier, and a refused run should degrade to
a fallback model rather than produce no report; if the server rejects the beta parameters
outright, the provider retries once without them rather than failing the whole run.

The OpenAI-facing providers exist because `/v1/chat/completions` compatibility mode has
real gaps against reasoning models (rejecting `max_tokens` in favor of
`max_completion_tokens`, requiring an explicit `reasoning_effort` to keep tool calling and
reasoning coexisting) — `openai_compatible.py` carries the workarounds as configurable
settings, while `openai_provider.py` targets `/v1/responses` natively and reuses
`DAWNPATROL_AI_EFFORT` directly for `reasoning.effort` since the accepted value range
matches. Cache-token accounting differs by convention between the two families and each
provider's `estimate_cost()` override accounts for it correctly: Anthropic's
`input_tokens` **excludes** cache reads (additive), OpenAI's `input_tokens` **includes**
them (inclusive) — a naive shared formula would silently double-bill every cached token
on one side or the other.

### 6.2 Prompt structure and caching

Ordered for maximum cache hit rate — stable content first:

```
system_static     [stable, cached]      system.md: role, severity taxonomy, epistemics
system_context     [semi-stable, cached]  profile.yml rendered as network context (+ notebook, if enabled)
user_message       [volatile]            evidence bundle + task instruction
(tool turns)        [volatile]            tool call / result pairs
```

`Profile.as_context()` is required to be deterministic — no timestamps, run IDs, or
counts before the cache breakpoint — because that's the classic silent cache invalidator:
one varying token anywhere in the stable prefix and every day pays the full input price
again. The system prompt plus profile is a few thousand tokens that are byte-identical
every day until the profile itself is edited, so day two onward reads them at the cache
rate; `usage.cache_read_tokens` being nonzero from the very first multi-turn run (the
breakpoint is hit within a single run's own tool loop, before a second day ever arrives)
is treated as something worth watching — a regression there is a real, visible cost
regression, not a curiosity.

### 6.3 Tools

Built per-run by `agent/tools.py`'s `ToolBox`, registered conditionally based on what's
actually configured this run:

| Tool | Purpose | Guard |
|---|---|---|
| `describe_schema()` | event-store columns, kinds present | — |
| `query_events(sql)` | one read-only SELECT against the run's own database | `agent/sqlguard.py`: single statement, `AGENT_READABLE` allowlist, run_id-value binding required for `events`, injected `LIMIT` |
| `sample_events(signal_id, n)` | raw events backing a signal | n ≤ 50 |
| `get_entity_history(value)` | first_seen, occurrences, prior findings for one IP/domain | — |
| `get_metric_history(key, days)` | one metric's own time series | days ≤ 365 |
| `hunt_history(domain=None, ip=None, days=180)` | long-term retained history beyond this run's raw events | exactly one of `domain`/`ip` |
| `get_device_directory(ip=None)` | full per-device detail, one IP or all known this run | only registered if any device was contributed this run |
| `enrich_ip(ips)` / `enrich_domain(domains)` | reputation lookups | budget + cache + prefilter enforced by the broker; only registered if an enricher covers that subject type |
| `add_notebook_entry(text)` | write a note next run's context will carry | only registered when `DAWNPATROL_MCP_NOTEBOOK_ENABLED=true`; capped at `DAWNPATROL_MCP_NOTEBOOK_MAX_ENTRY_CHARS` |
| `submit_analysis(...)` | terminal — ends the loop | parameters ARE the schema (§6.5) |

Every non-terminal call is charged against one shared per-run budget
(`DAWNPATROL_AI_MAX_TOOL_CALLS`, default 25); the call over budget returns a structured
message telling the model to submit with what it has rather than erroring the run.

`query_events` as read-only SQL rather than a fixed set of canned queries is a deliberate
choice: it lets the model chase a hypothesis it forms mid-run — "which clients queried
this domain, and did any of them also appear in the drop log?" — without every such
question having been anticipated in advance. The safety is structural, not behavioral:
single statement (no semicolons), a forbidden-keyword blocklist, a table allowlist, an
injected `LIMIT`, and — for `events` specifically — the query must bind `run_id` to an
exact value, not merely mention the column name (a substring check would let a query read
raw events from every run still inside the retention window, not just this one). The
underlying connection is opened read-only regardless, so this is a read-scope guarantee
layered on top of an actually-enforced one, not the only thing standing between the model
and a write.

Note what is *not* a tool: no shell, no filesystem, no arbitrary network fetch, and no
delivery tool. Delivery happens after adjudication, entirely in code, to recipients that
come from environment variables — so no amount of injected text anywhere in a log line
can redirect where a report goes. Two tools have effects that outlast this run's own
output: `enrich_ip`/`enrich_domain` (spend against a shared budget, and a cache write) and,
when enabled, `add_notebook_entry` — the one tool that writes state a *future* run reads
back as context rather than just this run's own budget. See §12 for why that one gets a
separate opt-in.

### 6.4 The evidence bundle

`agent/bundle.py` assembles the single user-turn message: a `RUN` header (window, whether
a baseline exists), `SOURCE HEALTH`, a `DEVICE DIRECTORY` summary if any devices were
seen, up to 60 `ANALYZER SIGNALS` (ranked by severity then confidence, canary signals
excluded), `METRICS` grouped by report section with prior-value deltas where available,
`WATCHLIST CARRIED FORWARD` if anything's outstanding, `ENRICHMENT BUDGET` remaining per
enricher, and up to 40 `ANALYZER NOTES`. Untrusted content — domain names, log messages,
ISP strings — only ever appears inside this bundle or inside a later tool result, fenced
between `<<<DATA`/`DATA>>>` markers, with an explicit instruction that content inside them
is data to analyze, never instructions to follow. It never appears in the system prompt.

The device directory (`devices.py`) itself is a per-run, in-memory registry keyed by IP,
built fresh every run — any source's `collect()` can call `ctx.devices.update(ip,
source=..., role=..., hostname=..., ...)` to contribute whatever it happens to know.
Contributions merge rather than overwrite (first non-empty value per field wins, every
contributing source and role is recorded), and public IPs are declined by default
(`DAWNPATROL_DEVICES_INCLUDE_PUBLIC_IPS=false`) since this directory describes your own
network, not a remote host a source happens to monitor. **The human-facing report does
not render the device list at all** — an earlier version did, and that made a real gap
look like completeness: a NAT-gated segment with no SNMP presence and no local resolver
behind it can have real active traffic while contributing zero entries to `ctx.devices`,
because nothing in that segment's traffic ever registers as a device in the traditional
sense. `segment_review.py` computes a real **segment population** instead — distinct
client counts by DNS and by firewall, counted on both sides of a flow specifically
because some gateways log only `DROP`/`REJECT`, never `ACCEPT` — and that's what actually
answers "is anything out there," not "what happens to be in the device list." The device
directory is still fully available through `report.devices` in JSON, the
`get_device_directory` agent tool, and the MCP tool of the same name — it just isn't the
thing the report body renders.

### 6.5 Structured output

The agent's final answer arrives as a call to a tool, not as provider-native structured
output: `submit_analysis` is registered with `terminal=True` and its `parameters` field
*is* the JSON schema (`agent/schema.py`'s `ANALYSIS_SCHEMA`). Using a tool for the answer
— rather than each provider's own response-format mechanism — keeps every provider on the
identical code path and works even against a backend with no native JSON-schema support.

```jsonc
{
  "executive_summary": "string, 2-3 sentences",
  "findings": [ { "title": "...", "severity": "HIGH", "confidence": "high",
                  "taxonomy": "...", "zone": "...",
                  "signal_ids": ["fw.prober.203.0.113.45.22"],   // REQUIRED, ≥1
                  "evidence_kinds": ["local_behavior", "reputation"],
                  "what": "...", "why": "...", "not_this": "...", "action": "...",
                  "entities": [ {"type": "ip", "value": "...", "role": "source"} ] } ],
  "section_narratives": { "perimeter": "...", "dns": "...", "router": "...",
                          "segments": "...", "correlation": "..." },
  "trend_notes": [ {"kind": "ESCALATING", "text": "...", "signal_ids": [...]} ],
  "recommended_actions": [ {"priority": 1, "text": "...", "command": "..."} ],
  "watchlist_updates": [ {"entity_type": "ip", "entity_value": "...",
                          "reason": "...", "expires_days": 7} ],
  "watchlist_removals": [ {"entity_type": "ip", "entity_value": "...", "reason": "..."} ],
  "data_quality_notes": [ "..." ]
}
```

`watchlist_updates`/`watchlist_removals`' `entity_type` is `ip`, `domain`, or `host`;
`correlation.py`'s watchlist matcher treats `host` the same way it matches `ip` (against
`src_ip`/`dst_ip`/`client_ip`), since `Event.device` isn't a reliable hostname field for
every source.

The model writes judgment and prose fragments. It never writes headings, never writes a
number that belongs to a metric, and never writes the report envelope — every statistics
section is rendered straight from the `Metric` objects the analyzers already produced.
That's what makes "every number in the report traces to code" a property of the system by
construction, not a prompt rule the model is asked to follow.

### 6.6 Cost model

Measured live against a real deployment (at the time, ~28k firewall records and ~140k DNS
queries per 24h window — volume scales with network size, and will differ for yours),
Anthropic Opus 5 pricing ($5/MTok input, $25/MTok output, cache reads at $0.50/MTok):

| Run | Effort | Model calls | Input | Output | Cache read | Cost |
|---|---|---|---|---|---|---|
| Scheduled, medium effort | `medium` | 5-6 | ~131k | ~11.8k | ~30.5k | **$0.51-0.56** |
| Scheduled, high effort | `high` | 6 | ~273k | ~14.4k | ~61k | **$0.97-1.21** |

At daily cadence that lands around **$15-36/month** for `high`, **$15-17/month** for
`medium`. Levers, in the order worth reaching for:

1. `DAWNPATROL_AI_EFFORT` — `medium` for routine days.
2. `DAWNPATROL_AI_MAX_TOOL_CALLS` — caps investigation loop length.
3. `DAWNPATROL_AI_TASK_BUDGET_TOKENS` — the model paces itself against a ceiling.
4. `DAWNPATROL_AI_MAX_COST_USD` — hard abort (`budget.py`); the run still produces a
   deterministic-only report, never nothing.
5. `DAWNPATROL_AI_MODEL` — `claude-sonnet-5` or `claude-haiku-4-5`, or a different
   provider entirely (§5.5).

A run that trips the cost ceiling degrades to "analyzer signals rendered without agent
narrative," flagged plainly in the data-quality section — it never produces no report at
all.

---

## 7. Guardrails and adjudication

`adjudicate.py` runs after the agent (stage 8) and before rendering. Every rule the
system otherwise depends on the model following becomes a validator here instead — the
difference is that a validator holds every time, and a clamp or rejection is recorded so
you can see when the model tried to over-reach.

| Rule | Enforcement |
|---|---|
| A finding must trace to real data | `signal_ids` resolves to at least one known `Signal`; a finding citing none is rejected outright |
| Reputation alone never creates a finding | `evidence_kinds` must intersect `{local_behavior, baseline_delta, correlation, policy_violation}`; a finding backed only by `reputation` is rejected |
| Severity may exceed its strongest signal's hint by at most one level | clamped; the clamp is recorded as an adjustment |
| CRITICAL requires local evidence of compromise | a finding whose only non-reputation evidence is `baseline_delta` cannot be CRITICAL on reputation alone — lowered to HIGH with a recorded reason |
| Country is never treated as a severity input | if a country/region name appears in `why` on a MEDIUM+ finding, a note is appended — the finding itself is not touched, since geography can legitimately appear as *context* |
| Overall status rollup | `RED` if any CRITICAL, ≥2 HIGH, or a canary failed; `AMBER` if any HIGH or ≥3 MEDIUM; else `GREEN` |
| No credential ever reaches output | the fully rendered body is scanned against every registered secret value before delivery; a hit aborts the run |
| Suppressed findings stay visible, not deleted | matched findings move to a one-line appendix; the underlying pattern is never silently dropped |

**Suppression** exists because its absence is how these systems die in practice: a
finding that turns out to be benign-but-weird gets `dawnpatrol suppress --taxonomy ...
--entity ... --reason "..." --days 90`, which writes a matcher, not a permanent
exception — every suppression carries a mandatory expiry that forces periodic
re-examination, and a match still shows up as one line in the report's appendix rather
than disappearing. Without that combination, the same false positive either reappears
every single morning until you stop reading the report, or gets silenced in a way nobody
revisits — both worse than the noise itself.

---

## 8. Self-validation (canaries)

A pipeline that reports GREEN for 200 consecutive days is indistinguishable from a
pipeline that's silently broken, and both the model and the reader eventually stop
paying attention. `canary.py` closes that loop by injecting synthetic activity every run
and asserting it gets detected.

```python
class Canary(ABC):
    name: str
    expect_taxonomy: str
    requires_kinds: frozenset[EventKind]

    @abstractmethod
    def inject(self, window: Window) -> tuple[list[Event], CanaryToken]: ...
    def assert_detected(self, signals: list[Signal], token: CanaryToken) -> CanaryResult: ...
```

Two ship, both using RFC 5737 TEST-NET / RFC 2606 `.invalid` addresses and names so they
can never collide with real traffic: `BeaconCanary` (`dns_beacon`) injects a perfectly
periodic DNS pattern the beaconing analyzer must notice (`c2.beacon_candidate`), and
`ProberCanary` (`persistent_prober`) injects 400 sustained drops to one port from one
source, the textbook shape `firewall_patterns.py` is built to catch
(`scan.persistent_prober`). Canary events are injected alongside real collection (stage
2), analyzed in a completely separate query pass scoped to only the canary source, and
tagged `is_canary=True` on any signal whose entities match — which is what keeps them out
of the evidence bundle and the report's own statistics entirely, not just hidden from the
final text.

The result goes in the report header, not buried in a data-quality footnote:

```
Detection self-test        : 2/2 canaries detected
```

A failed canary is itself a CRITICAL finding and forces `RED`: it means the pipeline
isn't detecting something it is definitionally supposed to detect, so every GREEN since
the last successful canary is unverified. `DAWNPATROL_CANARY_EVERY_N_RUNS` (default 1)
controls how often this runs, since it costs almost nothing. See
`docs/components/canaries.md` for how canary isolation is implemented and a worked
example of adding a new one — extending this list currently means editing `canary.py`
directly and adding to `BUILTIN_CANARIES`, since (unlike the five plugin folders in §5) it
isn't a discovered package.

---

## 9. Configuration

**Runtime knobs and secrets: environment variables**, resolved in `config.py`. Every
secret-shaped one also accepts a `_FILE` suffix
(`DAWNPATROL_SOURCE_LIBRENMS_TOKEN_FILE=/run/secrets/librenms`) for Docker/Podman
secrets, and the `_FILE` form wins when both are set.

```bash
# Schedule
DAWNPATROL_SCHEDULE="0 6 * * *"        # cron; empty = run once and exit
DAWNPATROL_TZ="UTC"
DAWNPATROL_RUN_ON_START=true
DAWNPATROL_WINDOW_HOURS=24             # code default; a source's own max_window_hours may clamp it further

# Paths — keep these absolute; a relative value resolves against the
# container's WORKDIR (/app), not against whatever you bind-mounted at
DAWNPATROL_DATA_DIR=/var/lib/dawnpatrol
DAWNPATROL_OUTPUT_DIR=/out
DAWNPATROL_PROFILE=/etc/dawnpatrol/profile.yml

# Retention
DAWNPATROL_RETENTION_RAW_DAYS=7
DAWNPATROL_RETENTION_IOC_DAYS=180
DAWNPATROL_RETENTION_METRICS_DAYS=730

# AI
DAWNPATROL_AI_PROVIDER=anthropic       # or openai / openai_compatible
DAWNPATROL_AI_MODEL=claude-opus-5
DAWNPATROL_AI_API_KEY=...              # falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY
DAWNPATROL_AI_EFFORT=high
DAWNPATROL_AI_MAX_COST_USD=3.00
DAWNPATROL_AI_MAX_TOOL_CALLS=25

# Sources — presence of required vars auto-enables the plugin
DAWNPATROL_SOURCE_LIBRENMS_URL=http://librenms.example/api/v0
DAWNPATROL_SOURCE_LIBRENMS_TOKEN=...
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

# MCP — off by default; see §12
DAWNPATROL_MCP_ENABLED=false
DAWNPATROL_MCP_PORT=8420
```

**Network topology: a mounted YAML profile**, everything true about *your* network that
must never land in a public repo. It's data the analyzers and the model read, never
executable.

```yaml
site: { name: "home", timezone: "UTC" }

zones:
  - name: iot
    cidrs: ["192.168.50.0/24"]
    trust: untrusted
    gateway: "192.168.1.8"
    notes: "Cameras and home automation. Unpatchable and chatty. Highest-risk
            segment. Expected egress: a small stable set of vendor cloud
            endpoints plus NTP. Anything else is notable."
    expected_egress_domains: ["*.vendor-cloud.example", "*.pool.ntp.org"]

hosts:
  - { ip: "192.168.1.1", role: "router/firewall/vpn", model: "Example RT-1234" }
  - { ip: "192.168.1.53", role: "dns-resolver", authoritative_resolver: true }

policy:
  wan_ip_is_dynamic: true              # a WAN IP change is not an incident
  approved_resolvers: ["192.168.1.53"]
  attack_surface_ports: [22, 23, 80, 443, 445, 1194, 3306, 3389, 5060, 5432, 5900, 8080, 8443, 8728]
  nat_attribution_limited_behind: []   # see caveat below
  benign_domain_suffixes: [...]        # REPLACES the built-in default list, not additive

known_quirks:
  - "Some consumer router firmware mislabels routine roaming/watchdog chatter
     as 'emerg' severity. Break emerg counts down by program before concluding."
```

`nat_attribution_limited_behind` is what turns the attribution-limit caveat from a prompt
rule into automatic renderer behavior — any finding whose subject is one of those
addresses gets the "traffic is NATed here; per-device attribution is not possible"
language attached without the model having to say it. **List a gateway here only after
verifying its own logs genuinely cannot reveal the originating client** — a NAT gateway
does not automatically mean the client behind it is unknowable. Two OpenWrt gateways in a
real deployment were listed here on exactly that assumption, then removed once their own
kernel/iptables logs turned out to carry the real pre-NAT client address in `SRC=`/`DST=`
the whole time; the mechanism stayed, the assumption that put entries in it didn't.

`benign_domain_suffixes` is a **full override**, not an addition — setting it replaces
the built-in default list rather than extending it, so a deployment that sets it needs to
re-list anything from the default it still wants. `known_quirks` is a place to record
environment truths without touching a prompt; every entry is injected into the cached
profile block verbatim. See `docs/components/profile.md` for every field's effect on
analysis in detail.

---

## 10. CLI and operations

```bash
dawnpatrol serve                        # scheduler loop (default)
dawnpatrol run                          # one full run now
dawnpatrol run --stop-after analyze     # no API spend; dumps the evidence bundle
dawnpatrol run --dry-run                # everything except real delivery
dawnpatrol run --ephemeral              # real run, real delivery — deletes its own DB rows/files after
dawnpatrol delete-run <id> [--force]    # delete one run's rows and report files on demand
dawnpatrol runs                         # recent run history
dawnpatrol canary                       # last detection self-test
dawnpatrol probe                        # connectivity + auth check on every source
dawnpatrol list-plugins                 # what was discovered and whether it is enabled
dawnpatrol validate                     # config and profile validation
dawnpatrol hunt --domain x --days 180   # retrospective IOC search over the long-term store
dawnpatrol suppress --reason "..." --days 90 --taxonomy scan.persistent_prober
```

`--ephemeral` and `delete-run` exist so iterating against the real deployment doesn't
leave months of throwaway history on disk (§4 covers exactly which tables they clear, and
the one table — `entities` — that neither one can retroactively undo). `--ephemeral`
still collects, analyzes, and delivers for real against the real database; add
`--dry-run` too if a test run also shouldn't actually email or POST anywhere.
`delete-run` does the identical cleanup after the fact against any run still on disk, and
refuses one that has no recorded finish time (looks still in progress) unless `--force`
is passed.

`--stop-after <stage>` (any of `collect`/`verify`/`persist`/`analyze`/`investigate`/
`adjudicate`/`render`/`deliver`) is the fast development loop: `--stop-after analyze`
gives a full evidence bundle — metrics, signals, source health — with zero API spend,
which is the right way to develop and sanity-check a new analyzer or source normalizer.

Suppressions carry a mandatory expiry, and matching findings move to a report appendix
rather than being deleted, so a tuned-out pattern that changes character stays visible
(§7). Delivery policy is per-output: `DAWNPATROL_OUTPUT_<NAME>_RUN_WHEN=ALWAYS|NEVER|
IMPORTANT|AMBER,RED`.

---

## 11. Container and scheduling

**Scheduling is in-process** (`scheduler.py`) — `croniter` plus a sleep loop, rather than
cron or supercronic as a separate process. One process, PID 1 is the app, logs go to
stdout unmodified, signal handling is straightforward, and the schedule is a plain env
var. `DAWNPATROL_SCHEDULE=""` runs once and exits — useful for testing, or for driving
DawnPatrol from an external scheduler instead. The loop wakes at least every 60 seconds
even during a long gap between runs, purely to keep the heartbeat file fresh and honor a
stop signal promptly.

```dockerfile
FROM python:3.12-slim
RUN useradd -r -u 10001 dawnpatrol
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY dawnpatrol/ ./dawnpatrol/
USER dawnpatrol
ENV DAWNPATROL_DATA_DIR=/var/lib/dawnpatrol \
    DAWNPATROL_OUTPUT_DIR=/out \
    DAWNPATROL_PROFILE=/etc/dawnpatrol/profile.yml
VOLUME ["/var/lib/dawnpatrol", "/out"]
HEALTHCHECK --interval=5m CMD python -m dawnpatrol.cli healthcheck
ENTRYPOINT ["python", "-m", "dawnpatrol.cli"]
CMD ["serve"]
```

Single stage, slim base, non-root, no build toolchain in the final image. `healthcheck`
reads the same heartbeat file the scheduler touches, so a wedged scheduler is visible to
Docker without a second monitoring path. The three path variables baked into the image
(`DATA_DIR`/`OUTPUT_DIR`/`PROFILE`) are absolute and match the `VOLUME` declarations and
`docker-compose.yml`'s own mount points — overriding any of them with a relative value in
`.env` resolves against the container's `WORKDIR` (`/app`) instead of wherever you
actually bind-mounted, which silently sends a run's database and report files into the
container's ephemeral filesystem. Keep overrides absolute, or don't override them.

---

## 12. External agent access (MCP)

Everything above describes one closed loop: collect, reduce, judge, report, deliver, on a
schedule. That loop produces a good morning briefing. It's a poor fit for the moment a
briefing says something worth digging into, because digging in means re-running
collection with different parameters, writing ad hoc SQL against events the pipeline
already has, or re-checking the network profile against a hunch — none of which should
require shelling into the box or re-deriving context a second AI system already built.

`dawnpatrol/mcpserver/` answers that with a second, optional interface onto the same
capabilities: an MCP server over streamable HTTP that an external agent — a human's own
Claude session, an incident-response bot, a SIEM's enrichment step — can call directly.
It is not a new capability surface; every tool is a thin wrapper over something the
pipeline already does:

| Tool | Wraps |
|---|---|
| `list_reports`, `get_latest_report`, `get_report` | the files `file_report.py` already writes |
| `describe_event_schema`, `query_events` | the identical `agent/sqlguard.py` validator the in-run agent's SQL tool uses (§6.3) |
| `get_metric_history` | `Store.metric_history` |
| `get_network_profile` | `Profile.as_context()` — the same text block cached into the harness system prompt |
| `list_source_plugins` | `registry.discover` + `env_satisfied` — the same introspection `list-plugins` uses |
| `get_device_directory` | `Report.devices` in `latest.json` — not a live, plugin-specific lookup |
| `read_notebook`, `add_notebook_entry`, `delete_notebook_entry` | the `notebook` table — a second, narrower door (below) |
| `trigger_analysis` | `Runner.run()` — the identical pipeline a scheduled run executes |

Two things carry the actual safety weight. **It's one door onto existing rooms, not a new
room.** `trigger_analysis` cannot make the pipeline do anything `dawnpatrol run` at a
terminal couldn't already do, and `query_events` cannot reach a table or bypass a rule
`agent/sqlguard.py` doesn't already enforce for the in-run investigation agent itself —
auditing the MCP surface is auditing whether the wrapping is thin, not auditing a second
implementation of read access. And **it's the one thing in this design that listens, so
it defaults off and to authenticated**: `DAWNPATROL_MCP_ENABLED` must be set explicitly,
every request needs `Authorization: Bearer <token>` checked with a constant-time
comparison (`hmac.compare_digest`) in a small ASGI middleware wrapped *around* the MCP
app rather than inside it, and the token is either operator-supplied
(`DAWNPATROL_MCP_TOKEN`, stable across restarts) or generated fresh and logged exactly
once at startup.

`trigger_analysis` and the scheduled cron job share one real lock
(`threading.Lock` in `cli.cmd_serve`), so a triggered run arriving mid-cron gets a clean
"a run is already in progress" response instead of racing the scheduled one. It also
never sends email — `Runner.run(skip_outputs={"smtp"})` drops that output from the
delivery list before stage 10 runs at all, the same code path any other output-skip uses,
not a special case bolted onto the SMTP plugin. File output still happens, so the result
is retrievable afterward exactly like a scheduled run's.

**The notebook is a materially different trust boundary, and gated separately.** Every
other MCP tool is read-only, and even `trigger_analysis` only re-runs the existing
pipeline — it doesn't change what a *future* run believes going in.
`add_notebook_entry` does: text lands in the `notebook` table and is read back by
`agent/harness.py`, appended to the system context right after the profile, on every
subsequent run. There are two independent writers into that same table — this MCP tool,
and a second `add_notebook_entry` on the in-run investigation agent's own tool surface
(§6.3) — sharing the same gate and the same injection limits. Because shaping future
judgment is a different risk than reading data or spending API budget, it doesn't turn on
with `DAWNPATROL_MCP_ENABLED` — it needs its own `DAWNPATROL_MCP_NOTEBOOK_ENABLED`, off
by default even when the rest of the MCP surface is on. Two bounds keep it from becoming
an unbounded cost or context-injection surface:
`DAWNPATROL_MCP_NOTEBOOK_MAX_ENTRY_CHARS` rejects an over-long single note outright, and
`DAWNPATROL_MCP_NOTEBOOK_MAX_INJECTED` (default 50) caps how many of the most recent
entries actually get injected into any run's context even though the full history stays
readable via `read_notebook`. A note still cannot fabricate a finding —
`adjudicate.py`'s `signal_ids` requirement applies regardless of what the model was told
going in. `delete_notebook_entry` removes one immediately, no expiry mechanism, since a
note is context an agent retracts when it's stale or wrong, not a tuning rule that needs
its own audit trail the way a suppression does.

See `docs/components/mcp-server.md` for the full tool reference, deployment guidance, and
a worked example of adding a new tool.

---

## 13. Security posture

This reads attacker-influenced data by design, so a few things are worth stating plainly
rather than leaving implicit.

**Untrusted content handling.** Domain names, hostnames, ISP strings, and log messages
are attacker-influenced and are never interpolated into the system prompt — they arrive
only inside the evidence bundle and tool results, fenced, with a standing instruction
that content inside them is data, never instructions (§6.4). The structural defense does
the real work regardless: the model has no shell, no fetch, no filesystem, and no
delivery tool, so there's no action for injected text to trigger even if the instruction
were ignored. Delivery recipients come from environment variables and cannot be
influenced by run content (§5.4).

**Secret hygiene.** Secrets are read only from environment variables or their `_FILE`
form (`secrets.py`); `SecretStr` keeps them out of `repr()`/logs entirely. Before any
output plugin runs, the fully rendered report body is scanned against every registered
secret value, and a hit genuinely aborts delivery — this isn't advisory logging, `Runner`
returns before the DELIVER stage if a leak is detected. `config/profile.yml` (real
topology) and `.env` (real credentials) are gitignored; `.env.example` ships with
placeholders only.

**SQL tool.** Covered in full in §6.3: single statement, table allowlist, an actual
run_id-value binding requirement (not a substring check) for `events`, injected `LIMIT`,
and a connection opened read-only regardless.

**Egress.** The container talks to whatever monitoring hosts are configured, up to two
reputation APIs, the configured model provider's API, and your SMTP/webhook
destination — all env-configured, so egress can be firewalled to an explicit allowlist if
that matters for your deployment.

---

## 14. Testing

430 tests, `pytest -q`, fully offline — no network, no API key, no spend — including a
full end-to-end pipeline exercise against a stubbed provider. CI runs the same suite plus
`ruff` on every push and pull request.

- **Source parsers** — the failure modes real telemetry produces: an epoch-vs-string
  timestamp trap, cursor-pagination duplication, a malformed record, truncated
  pagination — each a dedicated test built from synthetic records constructed inline
  rather than recorded fixtures on disk, so every trap has a deterministic regression
  test without depending on a "scrubbed" real capture staying scrubbed.
- **Analyzers** against synthetic event sets with known-correct expected signals: a
  textbook persistent prober, a /24 sweep, conntrack return traffic, a stepped-TTL probe,
  a DGA burst.
- **Renderers** — property tests asserting 7-bit ASCII output, all sections present in
  order, no unsubstituted template tokens, every empty section carrying its documented
  empty-state line, and — for both HTML renderers — that attacker-influenced finding
  text is escaped rather than passed through as markup.
- **Adjudication** — each guardrail in §7 gets a test feeding it a deliberately
  non-compliant agent response and asserting the clamp or rejection actually fires.
- **The MCP surface** — every tool's logic against a real temp-directory store, plus the
  bearer-auth middleware against a raw ASGI scope, with no real HTTP server started.
- **End-to-end** — a stubbed model returning a canned analysis, exercising the full
  pipeline with zero API spend, including the `--ephemeral`/`delete-run` cleanup path.
