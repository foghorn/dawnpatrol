"""Analyzer plugin contract.

Analyzers are the deterministic reduction layer: hundreds of thousands of events
in, a few dozen metrics and signals out. They are pure - no network, no model
calls - which makes them fast to iterate on and trivial to test against fixtures.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import AnalyzerResult, EventKind
from ..profile import Profile
from ..query import EventQuery
from .baseline import Baseline


class Analyzer(ABC):
    name: str = ""
    #: Skipped entirely when no source supplied these kinds.
    requires_kinds: frozenset[EventKind] = frozenset()
    #: Optional hard dependency on specific source plugins.
    requires_sources: frozenset[str] = frozenset()
    #: Lower runs first; use for analyzers that read others' output indirectly.
    order: int = 100

    @abstractmethod
    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        """Return metrics and signals. Must not raise for empty input."""

    def applicable(self, kinds: set[EventKind], sources: set[str]) -> bool:
        if self.requires_kinds and not (self.requires_kinds & kinds):
            return False
        if self.requires_sources and not (self.requires_sources & sources):
            return False
        return True

    def __repr__(self) -> str:
        return f"<Analyzer {self.name}>"
