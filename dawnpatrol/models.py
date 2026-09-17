"""Core data model.

One flat :class:`Event` type rather than per-source shapes. This is the decision
that makes cross-source correlation possible at all: a firewall event and a DNS
event must agree on what ``src_ip`` means before anything can correlate them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any

UTC = UTC


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class EventKind(StrEnum):
    FIREWALL = "firewall"
    DNS = "dns"
    SYSTEM = "system"
    AUTH = "auth"
    IDS = "ids"
    FLOW = "flow"
    HTTP = "http"
    OTHER = "other"


class Severity(IntEnum):
    """Ordered so severities can be compared and clamped arithmetically."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc

    def label(self) -> str:
        return self.name


class Status(StrEnum):
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class HealthState(StrEnum):
    """Deliberately four states, not two.

    ``SUSPECT`` exists so "the query returned zero rows" is never rendered as
    "the device stopped forwarding logs" - they are different claims and only
    the first is ever directly observed.
    """

    OK = "OK"
    DEGRADED = "DEGRADED"
    SUSPECT = "SUSPECT"
    FAILED = "FAILED"


class EntityType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HOST = "host"
    PORT = "port"
    DEVICE = "device"
    USER = "user"


class Verdict(StrEnum):
    BENIGN = "benign"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# --------------------------------------------------------------------------- #
# Time window
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Window:
    """A closed time interval, always UTC, always tz-aware."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("Window bounds must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("Window end must be after start")

    @classmethod
    def ending_now(cls, hours: int, now: datetime | None = None) -> Window:
        end = now or datetime.now(UTC)
        return cls(start=end - timedelta(hours=hours), end=end)

    @property
    def hours(self) -> float:
        return (self.end - self.start).total_seconds() / 3600.0

    def clamp_hours(self, max_hours: int | None) -> Window:
        """Shrink to at most ``max_hours``, keeping the end fixed.

        Used for sources with known retention limits (a DNS log that only holds
        24h should report a clamped window, not a 48h shortfall).
        """
        if max_hours is None or self.hours <= max_hours:
            return self
        return Window(start=self.end - timedelta(hours=max_hours), end=self.end)

    def last_hour(self) -> Window:
        return Window(start=self.end - timedelta(hours=1), end=self.end)

    def fmt(self, dt: datetime) -> str:
        return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def start_str(self) -> str:
        return self.fmt(self.start)

    @property
    def end_str(self) -> str:
        return self.fmt(self.end)

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end

    def __str__(self) -> str:
        return f"{self.start_str} -> {self.end_str} UTC ({self.hours:.2f}h)"


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Event:
    """A single normalized observation from any source."""

    ts: datetime
    source: str
    kind: EventKind
    dedup_key: str

    # network / firewall / flow
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None
    action: str | None = None
    iface_in: str | None = None
    iface_out: str | None = None
    ttl: int | None = None
    pkt_len: int | None = None

    # dns
    domain: str | None = None
    qtype: str | None = None
    blocked: bool | None = None
    block_reason: str | None = None
    upstream: str | None = None
    client_ip: str | None = None

    # host / system
    device: str | None = None
    program: str | None = None
    severity: str | None = None
    message: str | None = None
    user: str | None = None

    # derived from the site profile at normalize time
    src_zone: str | None = None
    dst_zone: str | None = None

    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError(f"Event.ts must be timezone-aware (source={self.source})")

    @staticmethod
    def make_dedup_key(source: str, *parts: Any) -> str:
        """Stable identity for a record, so re-collection is idempotent."""
        joined = "|".join("" if p is None else str(p) for p in parts)
        digest = hashlib.sha1(f"{source}|{joined}".encode()).hexdigest()
        return f"{source}:{digest[:20]}"


# --------------------------------------------------------------------------- #
# Collection results and health
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Probe:
    """One differential-test result, recorded verbatim.

    A source that returns zero rows must run its probes before anything is
    allowed to call it an outage.
    """

    name: str
    request: str
    ok: bool
    status: int | None = None
    records: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "request": self.request,
            "ok": self.ok,
            "status": self.status,
            "records": self.records,
            "detail": self.detail,
        }


@dataclass(slots=True)
class CollectionResult:
    """What a source produced, plus everything needed to verify it."""

    source: str
    events: list[Event] = field(default_factory=list)
    window: Window | None = None
    requested_window: Window | None = None
    reported_total: int | None = None
    pages: int = 0
    complete: bool = True
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def unique_count(self) -> int:
        return len({e.dedup_key for e in self.events})

    @property
    def span_hours(self) -> float:
        if not self.events:
            return 0.0
        stamps = [e.ts for e in self.events]
        return (max(stamps) - min(stamps)).total_seconds() / 3600.0

    @property
    def clamped(self) -> bool:
        """True when the source's own retention shortened the requested window."""
        if self.window is None or self.requested_window is None:
            return False
        return self.window.hours < self.requested_window.hours - 0.01


@dataclass(slots=True)
class SourceHealth:
    source: str
    state: HealthState
    records: int = 0
    unique_records: int = 0
    reported_total: int | None = None
    span_hours: float = 0.0
    requested_hours: float = 0.0
    pages: int = 0
    probes: list[Probe] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.state in (HealthState.OK, HealthState.DEGRADED)


# --------------------------------------------------------------------------- #
# Analysis products
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Entity:
    type: EntityType
    value: str
    role: str = ""  # "source", "destination", "client", ...

    def key(self) -> str:
        return f"{self.type}:{self.value}"

    def to_dict(self) -> dict[str, str]:
        return {"type": str(self.type), "value": self.value, "role": self.role}


@dataclass(slots=True)
class Metric:
    """A deterministic statistic. Rendered straight into the report."""

    key: str
    value: float | int | str
    section: str = "general"
    unit: str | None = None
    label: str | None = None
    prior: float | None = None

    @property
    def delta_pct(self) -> float | None:
        if self.prior in (None, 0) or not isinstance(self.value, (int, float)):
            return None
        return ((float(self.value) - float(self.prior)) / abs(float(self.prior))) * 100.0

    def display_label(self) -> str:
        return self.label or self.key


@dataclass(slots=True)
class Signal:
    """A deterministically-computed candidate finding.

    Every :class:`Finding` must reference at least one of these. That is the
    structural anti-fabrication measure: a finding that traces to no signal is
    rejected by the adjudicator rather than merely discouraged by a prompt.
    """

    id: str
    analyzer: str
    title: str
    taxonomy: str
    severity_hint: Severity = Severity.INFO
    confidence: float = 0.5
    entities: list[Entity] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    support: list[str] = field(default_factory=list)
    narrative_hint: str = ""
    first_seen: str | None = None
    days_recurring: int = 0
    is_canary: bool = False

    def to_bundle(self) -> dict[str, Any]:
        """Compact form handed to the model. Numbers, not prose."""
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "taxonomy": self.taxonomy,
            "severity_hint": self.severity_hint.label(),
            "confidence": round(self.confidence, 2),
            "entities": [e.to_dict() for e in self.entities],
            "evidence": self.evidence,
        }
        if self.narrative_hint:
            out["note"] = self.narrative_hint
        if self.first_seen:
            out["first_seen"] = self.first_seen
        if self.days_recurring:
            out["days_recurring"] = self.days_recurring
        return out


@dataclass(slots=True)
class AnalyzerResult:
    analyzer: str
    metrics: list[Metric] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class Enrichment:
    """Normalized reputation verdict, uniform across providers.

    Note what is absent: raw report counts. AbuseIPDB's ``totalReports`` is
    heavily inflated for cloud and security-vendor space and does not track the
    score. It stays in ``raw`` for audit; the model is never handed it, so it
    cannot misreport a number it was never given.
    """

    subject: str
    enricher: str
    found: bool = False
    score: int | None = None  # 0-100, higher is worse
    verdict: Verdict = Verdict.UNKNOWN
    whitelisted: bool = False
    categories: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    cached: bool = False
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        if self.error:
            return f"{self.subject}: lookup failed ({self.error})"
        if not self.found:
            return f"{self.subject}: no reputation data"
        bits = [f"score {self.score}/100" if self.score is not None else "score n/a"]
        if self.whitelisted:
            bits.append("whitelisted")
        if isp := self.attributes.get("isp"):
            bits.append(str(isp))
        if usage := self.attributes.get("usage_type"):
            bits.append(str(usage))
        if self.categories:
            bits.append("/".join(self.categories[:3]))
        return f"{self.subject}: " + ", ".join(bits)

    def to_bundle(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "enricher": self.enricher,
            "found": self.found,
            "score": self.score,
            "verdict": str(self.verdict),
            "whitelisted": self.whitelisted,
            "categories": self.categories,
            "attributes": self.attributes,
            "cached": self.cached,
            "error": self.error,
        }


@dataclass(slots=True)
class EnrichmentRef:
    subject: str
    enricher: str
    score: int | None
    verdict: str
    whitelisted: bool
    summary: str


# --------------------------------------------------------------------------- #
# Findings and reports
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Finding:
    """Produced by the agent, validated by the adjudicator."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    taxonomy: str
    what: str
    why: str = ""
    action: str = ""
    not_this: str = ""
    zone: str = "perimeter"
    signal_ids: list[str] = field(default_factory=list)
    evidence_kinds: list[str] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    enrichment: list[EnrichmentRef] = field(default_factory=list)
    # adjudication bookkeeping
    suppressed: bool = False
    suppressed_reason: str = ""
    adjustments: list[str] = field(default_factory=list)
    attribution_caveat: str = ""


@dataclass(slots=True)
class TrendNote:
    kind: str  # NEW | RECURRING | ESCALATING | RESOLVED
    text: str
    signal_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Action:
    priority: int
    text: str
    command: str = ""


@dataclass(slots=True)
class WatchlistUpdate:
    entity_type: str
    entity_value: str
    reason: str
    expires_days: int = 7


@dataclass(slots=True)
class WatchlistRemoval:
    entity_type: str
    entity_value: str
    reason: str = ""


@dataclass(slots=True)
class CanaryResult:
    name: str
    detected: bool
    detail: str = ""
    taxonomy: str = ""


@dataclass(slots=True)
class DeliveryResult:
    output: str
    ok: bool
    detail: str = ""
    skipped: bool = False


@dataclass(slots=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0

    def add(self, other: TokenUsage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.cost_usd += other.cost_usd
        self.calls += other.calls


@dataclass(slots=True)
class Report:
    """Everything the renderers need. Fully assembled before any output runs."""

    run_id: str
    generated_at: datetime
    window: Window
    status: Status = Status.GREEN
    findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    metrics: list[Metric] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    health: list[SourceHealth] = field(default_factory=list)
    devices: list[dict[str, Any]] = field(default_factory=list)
    executive_summary: str = ""
    section_narratives: dict[str, Any] = field(default_factory=dict)
    trend_notes: list[TrendNote] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    data_quality: list[str] = field(default_factory=list)
    canaries: list[CanaryResult] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    degraded: bool = False  # agent stage skipped or failed; stats-only report
    site_name: str = "network"

    # ----- convenience accessors used by renderers ------------------------- #

    def metrics_for(self, section: str) -> list[Metric]:
        return [m for m in self.metrics if m.section == section]

    def metric(self, key: str) -> Metric | None:
        for m in self.metrics:
            if m.key == key:
                return m
        return None

    def metric_value(self, key: str, default: Any = None) -> Any:
        m = self.metric(key)
        return default if m is None else m.value

    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.title))

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def canary_summary(self) -> str:
        if not self.canaries:
            return "not run"
        passed = sum(1 for c in self.canaries if c.detected)
        return f"{passed}/{len(self.canaries)} canaries detected"

    @property
    def canaries_ok(self) -> bool:
        return all(c.detected for c in self.canaries) if self.canaries else True

    def has_important(self) -> bool:
        """Whether this report warrants an alert-only delivery channel."""
        return (
            self.status in (Status.AMBER, Status.RED)
            or not self.canaries_ok
            or any(not h.usable for h in self.health)
        )

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at.astimezone(UTC).isoformat(),
            "site": self.site_name,
            "window": {
                "start": self.window.start_str,
                "end": self.window.end_str,
                "hours": round(self.window.hours, 2),
            },
            "status": str(self.status),
            "degraded": self.degraded,
            "executive_summary": self.executive_summary,
            "finding_count": self.finding_count,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.label(),
                    "confidence": str(f.confidence),
                    "taxonomy": f.taxonomy,
                    "zone": f.zone,
                    "what": f.what,
                    "why": f.why,
                    "not": f.not_this,
                    "action": f.action,
                    "signal_ids": f.signal_ids,
                    "evidence_kinds": f.evidence_kinds,
                    "entities": [e.to_dict() for e in f.entities],
                    "enrichment": [
                        {
                            "subject": r.subject,
                            "enricher": r.enricher,
                            "score": r.score,
                            "verdict": r.verdict,
                            "whitelisted": r.whitelisted,
                        }
                        for r in f.enrichment
                    ],
                    "adjustments": f.adjustments,
                }
                for f in self.findings_sorted()
            ],
            "suppressed": [
                {"id": f.id, "title": f.title, "reason": f.suppressed_reason}
                for f in self.suppressed_findings
            ],
            "metrics": [
                {
                    "key": m.key,
                    "value": m.value,
                    "unit": m.unit,
                    "section": m.section,
                    "prior": m.prior,
                    "delta_pct": m.delta_pct,
                }
                for m in self.metrics
            ],
            "sources": [
                {
                    "source": h.source,
                    "state": str(h.state),
                    "records": h.records,
                    "span_hours": round(h.span_hours, 2),
                    "requested_hours": round(h.requested_hours, 2),
                    "notes": h.notes,
                }
                for h in self.health
            ],
            "devices": self.devices,
            "trends": [
                {"kind": t.kind, "text": t.text, "signal_ids": t.signal_ids}
                for t in self.trend_notes
            ],
            "actions": [
                {"priority": a.priority, "text": a.text, "command": a.command}
                for a in sorted(self.actions, key=lambda a: a.priority)
            ],
            "data_quality": self.data_quality,
            "canaries": [
                {"name": c.name, "detected": c.detected, "detail": c.detail}
                for c in self.canaries
            ],
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "cache_read_tokens": self.usage.cache_read_tokens,
                "cost_usd": round(self.usage.cost_usd, 4),
                "model_calls": self.usage.calls,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=False)
