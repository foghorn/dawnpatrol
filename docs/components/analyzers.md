# Analyzers

Analyzers are the reduction layer: a day of real telemetry (roughly 28,000 firewall
lines plus 140,000 DNS queries against the network this was built for) becomes a few
dozen metrics and signals - the ~25k tokens of dense, numeric evidence the model actually
reasons over. They are pure functions: no network, no model calls, which is what makes
them fast to iterate on and trivial to test against synthetic data.

Nine ship today: `firewall_volume`, `firewall_patterns`, `dns_anomalies`, `novel_clients`,
`beaconing`, `auth_activity`, `segment_review`, `correlation`, `baseline_delta`. This
guide walks through `firewall_patterns.py` in full, because it exercises every part of
the contract, then shows you how to add another.

## The contract

```python
# dawnpatrol/analyzers/base.py
class Analyzer(ABC):
    name: str
    requires_kinds: frozenset[EventKind]     # skipped entirely if no source supplied these
    requires_sources: frozenset[str] = frozenset()   # optional harder dependency
    order: int = 100                         # lower runs first

    @abstractmethod
    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        """Return metrics and signals. Must not raise for empty input."""
```

`AnalyzerResult` carries `metrics: list[Metric]`, `signals: list[Signal]`, and
`notes: list[str]` (freeform data-quality observations that land in the report's final
section, not attached to any specific metric).

**`Metric`** is a number that goes straight into the report, no model in the loop:

```python
Metric(key="fw.drops.total", value=19824, section="perimeter",
      label="Firewall DROPs", unit=None)
```

`prior` gets auto-filled from `state.db` by the runner after every analyzer has run, so
you almost never set it yourself - day-over-day comparison is free.

**`Signal`** is a candidate finding - deterministically computed, not yet judged:

```python
Signal(
    id="fw.prober.203.0.113.45.22",       # stable slug; used for dedup and sample_events
    analyzer=self.name,
    title="Sustained probe from 203.0.113.45 against port 22",
    taxonomy="scan.persistent_prober",     # a vocabulary the model and adjudicator share
    severity_hint=Severity.MEDIUM,          # the agent may adjust, within adjudicate.py's clamp
    confidence=0.75,
    entities=[Entity(type=EntityType.IP, value="203.0.113.45", role="source")],
    evidence={...},                         # numbers and quoted samples only - no narrative
    narrative_hint="...",                   # guidance for the model, not shown to the reader
)
```

**Every `Finding` the model produces must cite at least one `Signal.id`.** That's not a
convention - `adjudicate.py` rejects a finding that doesn't, structurally, regardless of
how convincing the model's prose is. Anything you want the model to be *able* to report
has to originate as a signal here first.

## The query API: `EventQuery`

Analyzers never touch SQL directly. `EventQuery` (`dawnpatrol/query.py`) is a thin, typed
layer over one run's events, scoped by `run_id` automatically:

```python
q.count(kind=EventKind.FIREWALL, action="drop")
q.top("dst_port", n=15, by="unique:src_ip")     # ranked by distinct sources, not raw hits
q.hourly(kind=EventKind.FIREWALL, action="drop")
q.source_profile(n=60, action="drop")           # per-IP hits/ports/TTL-spread/timing
q.subnet_spread(n=12, action="drop")            # /24 buckets - the mass-sweep shape
q.dns_domain_stats(n=25, blocked=True)
q.dns_client_stats(n=40)                        # (client, total, blocked) per DNS client
q.distinct_count("src_ip", kind=EventKind.FIREWALL, src_zone="iot")   # a scalar count
q.distinct_values("dst_ip", kind=EventKind.FIREWALL, dst_zone="iot")  # the actual values
q.group_pairs("src_ip", "dst_port", n=50, action="accept")      # co-occurring column pairs
q.timestamps_for(limit=5000, kind=EventKind.DNS, client_ip="10.10.0.99")  # for periodicity
q.sample(n=20, src_ip="203.0.113.45")           # raw events backing a signal, for drill-down
```

`by="unique:<column>"` matters more than it looks: ranking by distinct source count
rather than raw hit count is the difference between "one host hit this port a lot" and
"many hosts probed this port," which is a materially different signal.

## Historical context: `Baseline`

```python
baseline.prior("fw.drops.total")           # this metric's value on the last completed run
baseline.novel(EntityType.DOMAIN, [...])   # which of these have never been seen before
baseline.recurrence("scan.persistent_prober", "203.0.113.45")   # how many prior runs
baseline.watchlist()                        # items a human or the agent flagged to track
```

This is what turns "RECURRING (day 4)" into a database count instead of a recollection,
and what makes newly-seen-domain detection a real query instead of a diff against
yesterday's notes.

## Walkthrough: `firewall_patterns.py`

Four behavioral shapes, classified from local evidence alone - reputation is applied
later, by the agent, and can only corroborate, never lead:

| Shape | Signature | Taxonomy |
|---|---|---|
| Persistent prober | one source, ≤3 ports, ≥50 hits, ≥2h, ≥70% concentration on one port | `scan.persistent_prober` |
| Mass scanner sweep | ≥15 sources in a /24, ≤4 hits/source average | `scan.mass_sweep` |
| Stepped-TTL probe | UDP, TTL ≤8 stepping by ≥4 across ≥10 hits | `scan.stepped_ttl` |
| Conntrack return | TCP sourced from port 80/443, benign by construction | no signal - just a metric and a note |

Sweep members are computed first and excluded from prober classification (`sweep_members`
in the code), so a scanner sweep never gets double-reported as forty individual probers.
Attack-surface ports (`profile.policy.attack_surface_ports`) raise a prober's severity
from LOW to MEDIUM - the only place policy from `profile.yml` feeds directly into a
severity hint.

## Build your own

Copy `dawnpatrol/analyzers/TEMPLATE.py`. The whole job is: query, decide, emit.

```python
class NewTLDAnalyzer(Analyzer):
    name = "new_tld_watch"
    requires_kinds = frozenset({EventKind.DNS})

    def run(self, q, profile, baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        domains = q.distinct_values("domain", limit=5000)
        tlds = {d.rsplit(".", 1)[-1] for d in domains if d}
        novel_tlds = baseline.novel(EntityType.DOMAIN, list(tlds))   # illustrative;
        # in practice you'd track TLDs as their own entity type or a dedicated table
        ...
        return r
```

Real advice, not boilerplate:

- **Emit a `Metric` even when nothing interesting happened.** A section with zero
  metrics renders as "no data for this section," which reads as a collection failure to
  someone glancing at the report. A metric of `0` with a clear label reads as "checked,
  clean."
- **Put judgment calls in `evidence` as numbers, not in `title` as adjectives.** The
  model decides whether `port_concentration: 0.94` is alarming; your job is to compute
  0.94 correctly and consistently, every day.
- **Use `order` only when you genuinely depend on another analyzer's side effects**
  (`firewall_patterns` runs at `order=20`, before analyzers that assume sweep membership
  is already known). Most analyzers don't need to care.
- **Never raise on empty input.** `applicable()` already skips your analyzer when its
  `requires_kinds` aren't present; inside `run()`, an empty result set is a normal day,
  not an error.

### Wire it up and test it

```bash
dawnpatrol run --stop-after analyze   # see your new signals/metrics, zero API spend
```

Add a test in `tests/test_analyzers.py`: build a synthetic `Event` list with a known,
deliberately-planted pattern (see `tests/conftest.py::make_events` for the existing
shapes - a sweep, a persistent prober, conntrack return, ordinary DNS, a beacon), run
your analyzer against it directly, and assert the expected signal appears with the
expected taxonomy. No database, no fixtures, no cost.
