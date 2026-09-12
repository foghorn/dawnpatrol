"""Historical context handed to every analyzer.

This is what replaces "search your notes for yesterday's numbers". Novel-entity
detection and day-over-day deltas are database queries, not recollection.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from ..models import UTC, EntityType
from ..store import Store


class Baseline:
    def __init__(self, store: Store, run_id: str, novelty_grace_hours: int = 1) -> None:
        self._store = store
        self._run_id = run_id
        self._grace = timedelta(hours=novelty_grace_hours)
        self._prior_metrics: dict[str, float] | None = None
        self._now = datetime.now(UTC)
        self._first_seen_cache: dict[tuple[str, str], datetime | None] = {}

    # ----- metrics ---------------------------------------------------------- #

    @property
    def prior_metrics(self) -> dict[str, float]:
        if self._prior_metrics is None:
            self._prior_metrics = self._store.prior_metric_values(self._run_id)
        return self._prior_metrics

    def prior(self, key: str) -> float | None:
        return self.prior_metrics.get(key)

    def has_baseline(self) -> bool:
        return bool(self.prior_metrics)

    def series(self, key: str, days: int = 30) -> list[dict[str, Any]]:
        return self._store.metric_history(key, days=days)

    # ----- entity novelty ---------------------------------------------------- #

    def first_seen_map(self, etype: EntityType, values: list[str]) -> dict[str, datetime]:
        wanted = [v for v in values if (str(etype), v) not in self._first_seen_cache]
        if wanted:
            found = self._store.entity_first_seen(etype, wanted)
            for v in wanted:
                self._first_seen_cache[(str(etype), v)] = found.get(v)
        return {
            v: self._first_seen_cache[(str(etype), v)]
            for v in values
            if self._first_seen_cache.get((str(etype), v)) is not None
        }

    def novel(self, etype: EntityType, values: list[str]) -> list[str]:
        """Values with no record before this run.

        The grace window matters: entities are written to the baseline during
        this same run, so anything first seen within the last hour is still
        "new today" rather than "already known".
        """
        if not values:
            return []
        seen = self.first_seen_map(etype, values)
        cutoff = self._now - self._grace
        return [v for v in values if v not in seen or seen[v] >= cutoff]

    # ----- findings and watchlist --------------------------------------------- #

    def recurrence(self, taxonomy: str, entity_value: str | None = None, days: int = 30) -> int:
        return self._store.finding_recurrence(taxonomy, entity_value, days=days)

    def prior_findings(self, entity_value: str, days: int = 90) -> list[dict[str, Any]]:
        return self._store.prior_findings_for(entity_value, days=days)

    def watchlist(self) -> list[dict[str, Any]]:
        return self._store.active_watchlist()

    def watched_values(self) -> set[str]:
        return {w["value"] for w in self.watchlist()}
