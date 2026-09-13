# Canaries

A pipeline that reports GREEN for 200 consecutive days is indistinguishable from a
pipeline that's silently broken, and both the reader and the model eventually stop
paying attention to either one. Canaries close that loop: inject a synthetic signal
whose detection is deterministic and verifiable, then assert the pipeline actually
detected it. `Detection self-test: 2/2 canaries detected` in the report header is a
database assertion, not a claim.

This isn't theoretical. During development, restricting a run to a single source
(`trigger_analysis(sources=["pihole_dns"])` over MCP, excluding the firewall source)
correctly produced `canary persistent_prober: NOT DETECTED` and escalated the report to
RED - because with no firewall analyzer running, nothing could have detected that
canary even if it had been real traffic. That's the mechanism working exactly as
designed: a GREEN status earned by accident is worse than a correctly-explained RED one.

Two canaries ship: `dns_beacon` (a perfectly periodic DNS pattern the beaconing
analyzer must catch) and `persistent_prober` (a textbook single-source, single-port
sustained probe the firewall-pattern analyzer must catch).

## The contract

```python
# dawnpatrol/canary.py
class Canary(ABC):
    name: str
    expect_taxonomy: str                    # the Signal.taxonomy a real analyzer must produce
    requires_kinds: frozenset[EventKind]     # only injected if a source can supply these

    @abstractmethod
    def inject(self, window: Window) -> tuple[list[Event], CanaryToken]:
        """Synthesize events a working analyzer must notice."""

    def assert_detected(self, signals: list[Signal], token: CanaryToken) -> CanaryResult:
        ...   # already implemented on the base class - see below
```

`assert_detected()` doesn't need overriding in practice: it scans the run's signals for
one whose `taxonomy` matches `expect_taxonomy` *and* whose entities intersect the
token's - both conditions, not just the taxonomy, so a canary can't accidentally "pass"
because some unrelated signal happened to share a taxonomy string.

## Why the addresses are reserved, not random

```python
CANARY_SRC = "192.0.2.77"                       # RFC 5737 TEST-NET-1
CANARY_CLIENT = "198.51.100.42"                  # RFC 5737 TEST-NET-2
CANARY_DST = "203.0.113.199"                     # RFC 5737 TEST-NET-3
CANARY_DOMAIN = "dawnpatrol-canary-beacon.invalid"   # RFC 2606 .invalid
```

These ranges are permanently reserved for documentation and can never be a real routable
address or a real registered domain - a canary event can never collide with genuine
traffic by construction, not by convention.

## How canary events stay invisible to everything that matters

This is the part worth understanding before writing a third canary, because it's easy
to get subtly wrong:

1. **Injection is source-gated.** `CanaryRunner.inject(window, kinds)` only injects a
   canary whose `requires_kinds` intersects the kinds actually collected this run - the
   same reasoning that made the MCP-restricted run above a legitimate NOT DETECTED
   rather than a false one.
2. **Real analysis excludes canary events entirely.** The runner queries with
   `EventQuery(store, run_id, exclude_sources={CANARY_SOURCE})` for every real metric
   and signal - a canary event can never inflate `fw.drops.total` or any other reported
   number.
3. **A second, isolated pass verifies detection.** A separate query
   (`only_sources={CANARY_SOURCE}`) runs the same analyzers over *only* the synthetic
   events, and `CanaryRunner.mark_signals()` tags any signal touching a canary entity as
   `is_canary=True` so it's excluded from both the evidence bundle the model sees and
   the rendered report.
4. **A failed canary is itself injected as a CRITICAL-equivalent flag** in the
   data-quality section (`adjudicate.py`'s rollup), because it means every GREEN since
   the last successful check is unverified - a failed self-test is never buried in
   section 10, it goes in the header.

## Build your own

Copy the shape of `ProberCanary` or `BeaconCanary` - both are under 40 lines. The steps:

1. **Pick `expect_taxonomy`** to match a taxonomy a real analyzer actually produces.
   Grep for the string in `analyzers/*.py` before you start; a canary that expects a
   taxonomy nothing emits will never pass and you'll spend an afternoon debugging the
   wrong file.
2. **Synthesize events inside the current window** that a correctly-working analyzer
   would classify with that taxonomy - reuse the reserved addresses above, or add a new
   RFC 5737/2606 constant if your canary needs a distinct one.
3. **Return a `CanaryToken`** naming the entities (IPs, domains, ports) a matching
   signal must reference.
4. **Register it** in `BUILTIN_CANARIES` in `canary.py` - there's no separate plugin
   discovery mechanism for canaries the way there is for the four folder-based plugin
   types, since there are only ever a handful and they're tightly coupled to specific
   analyzer taxonomies.

A canary worth adding next: one that exercises `dns_anomalies.py`'s DGA-shaped-domain
detection - a burst of high-entropy `.invalid` subdomains from the canary client,
expecting `dns.dga_suspect` (or whatever taxonomy that analyzer currently emits; check
first, per step 1).

### Wire it up and test it

```bash
dawnpatrol run --stop-after analyze   # canary injection and verification both run here
dawnpatrol canary                     # last detection self-test, on its own
```

`tests/test_canary_verify.py` is the pattern to follow: build a `CanaryRunner`, inject
against a real `Window`, feed the resulting events through the real analyzer whose
taxonomy you're targeting, and assert `assert_detected()` returns `detected=True` - then
assert it correctly returns `detected=False` when you feed it a signal set that
*doesn't* contain a match, so a canary that can't fail isn't actually testing anything.
