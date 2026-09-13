# Enrichment

Enrichers answer "what is this thing" about an IP, domain, URL, or hash - external
context, applied *after* an analyzer has already classified something from local
behavior. Reputation corroborates a conclusion; it never creates one. That rule is
enforced twice: by convention in every enricher, and structurally in
`adjudicate.py` (a finding whose only evidence is a reputation score is rejected
outright, and severity can move by at most one level on reputation alone).

Two ship today: `abuseipdb.py` (IP reputation) and `ismalicious.py` (domain
reputation). Both are budgeted, cached, and prefiltered by the framework - not by the
plugin, and definitely not by a prompt asking the model to be frugal.

## The contract

```python
# dawnpatrol/enrichment/base.py
class Enricher(ABC):
    name: str
    subject_types: frozenset[str]        # {"ip"} / {"domain"} / {"url"} / {"hash"}
    requires_env: frozenset[str]
    default_budget: int = 25             # lookups per run
    cache_ttl: timedelta = timedelta(days=7)
    batch_size: int = 1                  # >1 if the upstream API genuinely batches

    @abstractmethod
    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        """One entry per input subject. Mark failures with Enrichment.error,
        never drop a subject silently."""

    def prefilter(self, subjects: list[str]) -> list[str]:
        """Drop subjects this enricher cannot usefully answer."""
        return subjects
```

`Enrichment` (`dawnpatrol/models.py`) is the normalized verdict every consumer reads,
regardless of which enricher produced it:

```python
Enrichment(subject=, enricher=, found=, score=,        # 0-100, higher is worse
          verdict=Verdict.BENIGN | UNKNOWN | SUSPICIOUS | MALICIOUS,
          whitelisted=, categories=[...], attributes={...},
          raw={...}, cached=, error=)
```

**What's deliberately absent:** raw report-volume counters. AbuseIPDB's `totalReports`
and `numDistinctUsers` are heavily inflated for cloud and security-vendor address space
and don't track the score at all - an IP with 3,028 reports and a score of 0 is
whitelisted infrastructure, not a threat, and an IP with 215 reports and a score of 100
is a live Tor exit. Those counters live in `.raw` for audit; the normalized
`attributes` never carries them, so the model cannot misreport a number it was never
given.

## What the framework enforces so plugins don't have to

All three live in `enrichment/broker.py`, and none of them are optional:

- **Caching.** Every lookup is keyed `(enricher, subject)` in `state.db` with the
  enricher's own `cache_ttl`. Your top scanner IPs and busiest ad-tech domains are the
  same every day, so after the first week most lookups cost nothing.
- **Budget.** `DAWNPATROL_ENRICH_<NAME>_BUDGET` (default from `default_budget`). The
  lookup past the limit doesn't get refused silently - it comes back as a structured
  `Enrichment(error="lookup budget exhausted...")` the model can read and reason about,
  the same way any other tool result would be.
- **Prefiltering.** `abuseipdb.prefilter()` drops non-routable addresses (RFC1918,
  loopback) before they ever count against budget; a custom enricher should drop
  whatever it knows in advance it can't usefully answer. A wasted lookup is worse than a
  skipped one - it burns budget a real candidate needed.

`EnrichmentBroker.enrich(subject_type, subjects)` runs prefilter → cache lookup →
budget check → batched `lookup()` calls, in that order, and returns one `Enrichment` per
input subject regardless of which stage answered it.

## Walkthrough: `abuseipdb.py`

- **Score, not report count, drives `verdict`:** whitelisted → `BENIGN` outright;
  otherwise banded by `abuseConfidenceScore` (≥80 malicious, ≥50 suspicious, ≥25
  unknown, else benign). Country code is captured in `attributes` for context but is
  never a severity input - that's enforced by the adjudicator, not by omitting the
  field.
- **`prefilter()` drops non-routable addresses** via `profile.is_routable()`, so a
  private IP that slipped through never costs a lookup.
- **`max_age_days` defaults to 90 and stays fixed**, deliberately - report counts scale
  with the lookback window, so a varying window would make cross-run comparison
  meaningless even before you get to the score-vs-reports trap above.
- **A 429 or any request failure becomes an `Enrichment.error`**, never an exception -
  enrichment is advisory and must never be able to fail a run.

## Build your own

Copy `dawnpatrol/enrichment/TEMPLATE.py`. The whole job is the API call and the mapping
into `Enrichment` - caching, budget, and prefiltering are already handled for you.

```python
class VirusTotalEnricher(Enricher):
    name = "virustotal"
    subject_types = frozenset({"hash"})
    requires_env = frozenset({"DAWNPATROL_ENRICH_VIRUSTOTAL_KEY"})
    default_budget = 10
    cache_ttl = timedelta(days=30)

    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        ...  # call the API, map malicious-engine-count into a 0-100 score
```

The one design decision worth thinking through before you write `lookup()`: **what does
this upstream expose that looks like a verdict but isn't one?** AbuseIPDB's report
count was the first example found in production; assume your new source has its own
version and normalize it away rather than passing it through in `attributes`.

### Wire it up and test it

```bash
DAWNPATROL_ENRICH_VIRUSTOTAL_KEY=... dawnpatrol run --stop-after analyze
```

`--stop-after analyze` runs before enrichment (stage 7 is where the agent calls
`enrich_ip`/`enrich_domain`), so to exercise a new enricher directly, call
`EnrichmentBroker(...).enrich(subject_type, subjects)` from a small script or a test,
against a `Store` pointed at a temp SQLite file - no live run required. Test the budget
boundary explicitly: request one more subject than `default_budget` and assert the
overflow comes back with the `error` field set, not silently dropped.
