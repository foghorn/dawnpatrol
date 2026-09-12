"""Enrichment plugin contract.

Enrichers answer "what is this thing" about an IP, domain, or hash. The
framework - not the plugin, and definitely not the prompt - owns caching,
budget, and prefiltering, so an over-budget lookup is impossible rather than
merely discouraged.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import timedelta

from ..models import Enrichment
from ..profile import Profile

log = logging.getLogger(__name__)


class Enricher(ABC):
    name: str = ""
    #: "ip", "domain", "url", "hash"
    subject_types: frozenset[str] = frozenset()
    requires_env: frozenset[str] = frozenset()
    default_budget: int = 25
    cache_ttl: timedelta = timedelta(days=7)
    #: Subjects per upstream request. 1 means loop; >1 means a real batch API.
    batch_size: int = 1

    def __init__(self) -> None:
        self.profile: Profile = Profile()

    def configure(self, profile: Profile) -> None:
        self.profile = profile

    @abstractmethod
    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        """Fetch reputation for ``subjects``. Never raises for a single failure.

        Return one entry per input subject; mark individual failures with
        ``Enrichment.error`` rather than dropping them, so the caller can tell
        "no data" apart from "not asked".
        """

    def prefilter(self, subjects: list[str]) -> list[str]:
        """Drop subjects this enricher cannot usefully answer.

        A wasted lookup is worse than a skipped one: it burns budget that a real
        candidate needed.
        """
        return subjects

    def __repr__(self) -> str:
        return f"<Enricher {self.name}>"
