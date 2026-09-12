"""Detection self-validation.

A pipeline reporting GREEN for 200 days is indistinguishable from a pipeline
that is silently broken, and both the model and the reader eventually stop
paying attention. Canaries close that loop: inject a synthetic signal whose
detection is deterministic, then assert it was detected.

Injected events use addresses and names reserved for documentation (RFC 5737
TEST-NET, RFC 2606 .invalid) so they can never collide with real traffic, and
canary-derived signals are excluded from the evidence bundle and the report body.
A failed canary is itself a CRITICAL finding - it means every GREEN since the
last successful check is unverified.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .models import UTC, AnalyzerResult, CanaryResult, Event, EventKind, Window

log = logging.getLogger(__name__)

#: RFC 5737 TEST-NET-1/2/3 and RFC 2606 .invalid - never routable, never real.
CANARY_SRC = "192.0.2.77"
CANARY_CLIENT = "198.51.100.42"
CANARY_DST = "203.0.113.199"
CANARY_DOMAIN = "dawnpatrol-canary-beacon.invalid"
CANARY_SOURCE = "canary"


@dataclass(slots=True)
class CanaryToken:
    name: str
    entities: set[str] = field(default_factory=set)
    expect_taxonomy: str = ""
    detail: str = ""


class Canary(ABC):
    name: str = ""
    #: Taxonomy the responsible analyzer should produce.
    expect_taxonomy: str = ""
    #: Event kinds this canary needs an analyzer to be running for.
    requires_kinds: frozenset[EventKind] = frozenset()

    @abstractmethod
    def inject(self, window: Window) -> tuple[list[Event], CanaryToken]:
        """Synthesize events that a working analyzer must notice."""

    def assert_detected(self, signals: list[Any], token: CanaryToken) -> CanaryResult:
        for signal in signals:
            if signal.taxonomy != self.expect_taxonomy:
                continue
            values = {e.value for e in signal.entities}
            if token.entities & values:
                # On success, keep synthetic entity names out of the report:
                # the taxonomy is what the reader needs, and pasting canary
                # addresses into a security report invites misreading them as
                # real observations. The failure path below does name them,
                # because a failed canary has to be debuggable.
                return CanaryResult(
                    name=self.name, detected=True, taxonomy=self.expect_taxonomy,
                    detail=f"detected via {self.expect_taxonomy} ({token.detail})",
                )
        return CanaryResult(
            name=self.name, detected=False, taxonomy=self.expect_taxonomy,
            detail=(f"expected a {self.expect_taxonomy} signal naming one of "
                    f"{sorted(token.entities)}; none was produced"),
        )


class BeaconCanary(Canary):
    """A perfectly periodic DNS pattern. The beaconing analyzer must see it."""

    name = "dns_beacon"
    expect_taxonomy = "c2.beacon_candidate"
    requires_kinds = frozenset({EventKind.DNS})

    INTERVAL_SECONDS = 300
    SAMPLES = 60

    def inject(self, window: Window) -> tuple[list[Event], CanaryToken]:
        events: list[Event] = []
        # Place the series inside the window, ending before its end.
        span = timedelta(seconds=self.INTERVAL_SECONDS * self.SAMPLES)
        start = max(window.start, window.end - span - timedelta(minutes=5))
        for i in range(self.SAMPLES):
            ts = start + timedelta(seconds=self.INTERVAL_SECONDS * i)
            if ts >= window.end:
                break
            events.append(Event(
                ts=ts,
                source=CANARY_SOURCE,
                kind=EventKind.DNS,
                dedup_key=Event.make_dedup_key(CANARY_SOURCE, "beacon", i),
                domain=CANARY_DOMAIN,
                qtype="A",
                blocked=False,
                client_ip=CANARY_CLIENT,
                message="synthetic canary event",
            ))
        return events, CanaryToken(
            name=self.name,
            entities={CANARY_DOMAIN, CANARY_CLIENT},
            expect_taxonomy=self.expect_taxonomy,
            detail=f"{len(events)} queries at {self.INTERVAL_SECONDS}s intervals",
        )


class ProberCanary(Canary):
    """A textbook persistent prober: one source, one port, sustained for hours."""

    name = "persistent_prober"
    expect_taxonomy = "scan.persistent_prober"
    requires_kinds = frozenset({EventKind.FIREWALL})

    HITS = 400
    PORT = 22

    def inject(self, window: Window) -> tuple[list[Event], CanaryToken]:
        events: list[Event] = []
        duration = min(timedelta(hours=6), window.end - window.start)
        step = duration / max(1, self.HITS)
        start = window.end - duration
        for i in range(self.HITS):
            ts = start + step * i
            if ts >= window.end:
                break
            events.append(Event(
                ts=ts,
                source=CANARY_SOURCE,
                kind=EventKind.FIREWALL,
                dedup_key=Event.make_dedup_key(CANARY_SOURCE, "prober", i),
                src_ip=CANARY_SRC,
                dst_ip=CANARY_DST,
                src_port=40000 + (i % 5000),
                dst_port=self.PORT,
                proto="tcp",
                action="drop",
                iface_in="canary0",
                ttl=52,
                pkt_len=60,
                message="synthetic canary event",
            ))
        return events, CanaryToken(
            name=self.name,
            entities={CANARY_SRC, str(self.PORT)},
            expect_taxonomy=self.expect_taxonomy,
            detail=f"{len(events)} drops to port {self.PORT} over {duration}",
        )


BUILTIN_CANARIES: list[type[Canary]] = [BeaconCanary, ProberCanary]


class CanaryRunner:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.tokens: dict[str, CanaryToken] = {}
        self.canaries: list[Canary] = [c() for c in BUILTIN_CANARIES]

    def applicable(self, kinds: set[EventKind]) -> list[Canary]:
        return [c for c in self.canaries
                if not c.requires_kinds or (c.requires_kinds & kinds)]

    def inject(self, window: Window, kinds: set[EventKind]) -> list[Event]:
        if not self.enabled:
            return []
        events: list[Event] = []
        for canary in self.applicable(kinds):
            produced, token = canary.inject(window)
            if not produced:
                continue
            events.extend(produced)
            self.tokens[canary.name] = token
        if events:
            log.info("injected %d canary events across %d canaries",
                     len(events), len(self.tokens))
        return events

    def entity_values(self) -> set[str]:
        values: set[str] = set()
        for token in self.tokens.values():
            values |= token.entities
        return values

    def verify(self, signals: list[Any]) -> list[CanaryResult]:
        if not self.enabled or not self.tokens:
            return []
        results = []
        for canary in self.canaries:
            token = self.tokens.get(canary.name)
            if token is None:
                continue
            result = canary.assert_detected(signals, token)
            if result.detected:
                log.info("canary %s: detected", canary.name)
            else:
                log.error("canary %s: NOT DETECTED - %s", canary.name, result.detail)
            results.append(result)
        return results

    def mark_signals(self, results: list[AnalyzerResult]) -> None:
        """Tag canary-derived signals so they never reach the model or the report."""
        values = self.entity_values()
        if not values:
            return
        for result in results:
            for signal in result.signals:
                if any(e.value in values for e in signal.entities):
                    signal.is_canary = True
