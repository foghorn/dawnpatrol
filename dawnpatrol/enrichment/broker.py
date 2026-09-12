"""Enrichment broker: caching, budget, and prefilter enforcement.

The budget is enforced here, at the boundary, not requested in a prompt. The
26th lookup returns a structured "budget exhausted" result the model can read
and reason about. It cannot overspend, so the prompt does not need to ask it not
to - and a model that tries simply gets told no.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..models import Enrichment
from ..profile import Profile
from ..secrets import read_int
from ..store import Store
from .base import Enricher

log = logging.getLogger(__name__)


@dataclass(slots=True)
class EnrichmentStats:
    requested: int = 0
    served_from_cache: int = 0
    fetched: int = 0
    prefiltered: int = 0
    refused_over_budget: int = 0
    errors: int = 0
    by_enricher: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"{self.fetched} live lookups, {self.served_from_cache} from cache, "
            f"{self.prefiltered} prefiltered, {self.refused_over_budget} refused "
            f"(budget), {self.errors} failed"
        )


class EnrichmentBroker:
    def __init__(self, enrichers: list[Enricher], store: Store, profile: Profile,
                 enabled: bool = True) -> None:
        self.store = store
        self.profile = profile
        self.enabled = enabled
        self.stats = EnrichmentStats()
        self._by_type: dict[str, list[Enricher]] = {}
        self._budget: dict[str, int] = {}
        self._spent: dict[str, int] = {}
        for e in enrichers:
            e.configure(profile)
            env_key = f"DAWNPATROL_ENRICH_{e.name.upper()}_BUDGET"
            self._budget[e.name] = read_int(env_key, e.default_budget)
            self._spent[e.name] = 0
            for t in e.subject_types:
                self._by_type.setdefault(t, []).append(e)

    # ----- introspection ---------------------------------------------------- #

    def available_for(self, subject_type: str) -> list[str]:
        return [e.name for e in self._by_type.get(subject_type, [])]

    def remaining(self, enricher: str) -> int:
        return max(0, self._budget.get(enricher, 0) - self._spent.get(enricher, 0))

    def budget_report(self) -> dict[str, dict[str, int]]:
        return {
            name: {"budget": self._budget[name], "used": self._spent[name],
                   "remaining": self.remaining(name)}
            for name in self._budget
        }

    # ----- lookup ------------------------------------------------------------ #

    def enrich(self, subject_type: str, subjects: list[str]) -> list[Enrichment]:
        """Look up ``subjects``, honouring cache, prefilter, and budget."""
        if not self.enabled:
            return [Enrichment(subject=s, enricher="disabled",
                               error="enrichment is disabled for this run")
                    for s in subjects]

        enrichers = self._by_type.get(subject_type, [])
        if not enrichers:
            return [Enrichment(subject=s, enricher="none",
                               error=f"no enricher configured for {subject_type}")
                    for s in subjects]

        results: list[Enrichment] = []
        for enricher in enrichers:
            results.extend(self._enrich_one(enricher, subjects))
        return results

    def _enrich_one(self, enricher: Enricher, subjects: list[str]) -> list[Enrichment]:
        self.stats.requested += len(subjects)
        results: list[Enrichment] = []

        kept = enricher.prefilter(list(dict.fromkeys(subjects)))
        dropped = [s for s in subjects if s not in kept]
        self.stats.prefiltered += len(dropped)
        for s in dropped:
            results.append(Enrichment(
                subject=s, enricher=enricher.name,
                error="not a useful subject for this enricher (prefiltered)",
            ))

        pending: list[str] = []
        for subject in kept:
            cached = self.store.cache_get(enricher.name, subject)
            if cached is not None:
                self.stats.served_from_cache += 1
                results.append(_from_cache(cached, enricher.name))
            else:
                pending.append(subject)

        allowed = self.remaining(enricher.name)
        if len(pending) > allowed:
            refused = pending[allowed:]
            pending = pending[:allowed]
            self.stats.refused_over_budget += len(refused)
            for s in refused:
                results.append(Enrichment(
                    subject=s, enricher=enricher.name,
                    error=(f"lookup budget exhausted for {enricher.name} "
                           f"({self._budget[enricher.name]} per run). Prioritise "
                           f"subjects and try again next run."),
                ))

        for batch in _batches(pending, max(1, enricher.batch_size)):
            try:
                fetched = enricher.lookup(batch)
            except Exception as exc:  # noqa: BLE001 - enrichment is never blocking
                log.warning("enricher %s failed: %s", enricher.name, exc)
                self.stats.errors += len(batch)
                results.extend(
                    Enrichment(subject=s, enricher=enricher.name,
                               error=f"{type(exc).__name__}: {exc}"[:200])
                    for s in batch
                )
                continue

            self._spent[enricher.name] += len(batch)
            self.stats.fetched += len(batch)
            self.stats.by_enricher[enricher.name] = \
                self.stats.by_enricher.get(enricher.name, 0) + len(batch)

            for subject in batch:
                item = fetched.get(subject)
                if item is None:
                    item = Enrichment(subject=subject, enricher=enricher.name,
                                      error="enricher returned no result for this subject")
                if item.error:
                    self.stats.errors += 1
                elif item.found:
                    self.store.cache_put(enricher.name, subject, item.to_bundle(),
                                         enricher.cache_ttl)
                results.append(item)
        return results


def _from_cache(payload: dict, enricher: str) -> Enrichment:
    from ..models import Verdict

    try:
        verdict = Verdict(payload.get("verdict", "unknown"))
    except ValueError:
        verdict = Verdict.UNKNOWN
    return Enrichment(
        subject=payload.get("subject", ""),
        enricher=payload.get("enricher", enricher),
        found=bool(payload.get("found")),
        score=payload.get("score"),
        verdict=verdict,
        whitelisted=bool(payload.get("whitelisted")),
        categories=list(payload.get("categories") or []),
        attributes=dict(payload.get("attributes") or {}),
        cached=True,
    )


def _batches(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
