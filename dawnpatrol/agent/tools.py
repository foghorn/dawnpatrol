"""The agent's tool surface.

Note what is absent: no shell, no filesystem, no arbitrary fetch, and no
delivery tool. Delivery happens after adjudication, in code, to recipients that
come from environment variables - so no amount of injected text in a log line
can redirect a report. Two things outlast this run's own output: reputation
lookups against configured providers (spend, not state) and, when
DAWNPATROL_MCP_NOTEBOOK_ENABLED is set, add_notebook_entry - the one tool here
that writes state a future run will read back as context, not just this run's
budget.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..analyzers.baseline import Baseline
from ..devices import DeviceDirectory
from ..enrichment.broker import EnrichmentBroker
from ..models import Signal
from ..profile import Profile
from ..providers.base import SUBMIT_TOOL, ToolSpec
from ..query import EventQuery
from ..store import Store
from . import sqlguard
from .schema import ANALYSIS_SCHEMA

log = logging.getLogger(__name__)

MAX_ENRICH_PER_CALL = 10


class ToolBox:
    """Builds the tool specs and owns their handlers for one run."""

    def __init__(
        self,
        *,
        store: Store,
        query: EventQuery,
        profile: Profile,
        baseline: Baseline,
        broker: EnrichmentBroker,
        signals: list[Signal],
        run_id: str,
        max_calls: int = 25,
        devices: DeviceDirectory | None = None,
        notebook_enabled: bool = False,
        notebook_max_injected: int = 50,
        notebook_max_entry_chars: int = 4000,
    ) -> None:
        self.store = store
        self.query = query
        self.profile = profile
        self.baseline = baseline
        self.broker = broker
        self.signals = {s.id: s for s in signals}
        self.run_id = run_id
        self.max_calls = max_calls
        self.devices = devices if devices is not None else DeviceDirectory()
        self.notebook_enabled = notebook_enabled
        self.notebook_max_injected = notebook_max_injected
        self.notebook_max_entry_chars = notebook_max_entry_chars
        self.calls_made = 0
        self.call_log: list[str] = []

    # ----- budget ----------------------------------------------------------- #

    def _spend(self, name: str) -> str | None:
        self.calls_made += 1
        self.call_log.append(name)
        if self.calls_made > self.max_calls:
            return (f"Tool-call budget exhausted ({self.max_calls} calls per run). "
                    f"Submit your analysis now with what you have, and note the "
                    f"limitation in data_quality_notes.")
        return None

    # ----- handlers ---------------------------------------------------------- #

    def describe_schema(self, args: dict[str, Any]) -> str:
        if over := self._spend("describe_schema"):
            return over
        return sqlguard.describe_schema(self.run_id, self.store.settings.dialect)

    def query_events(self, args: dict[str, Any]) -> str:
        if over := self._spend("query_events"):
            return over
        sql = str(args.get("sql") or "")
        limit = int(args.get("limit") or sqlguard.DEFAULT_LIMIT)
        try:
            safe_sql, cap = sqlguard.validate(sql, self.run_id, limit)
        except sqlguard.SQLRejected as exc:
            return f"QUERY REJECTED: {exc}"
        try:
            columns, rows = self.store.readonly_sql(safe_sql, max_rows=cap)
        except Exception as exc:  # noqa: BLE001 - surface the error to the model
            return f"QUERY FAILED: {type(exc).__name__}: {str(exc)[:400]}"
        if not rows:
            return "0 rows. This means the query matched nothing, not that the data is absent."
        return json.dumps({"columns": columns, "row_count": len(rows),
                           "rows": rows}, default=str)[:20000]

    def sample_events(self, args: dict[str, Any]) -> str:
        if over := self._spend("sample_events"):
            return over
        signal_id = str(args.get("signal_id") or "")
        n = min(int(args.get("n") or 10), 50)
        signal = self.signals.get(signal_id)
        if signal is None:
            return (f"unknown signal_id {signal_id!r}. Known ids: "
                    f"{', '.join(sorted(self.signals)[:20])}")
        rows = self.query.sample_by_dedup(signal.support, n=n) if signal.support else []
        if not rows:
            rows = self._sample_from_entities(signal, n)
        return json.dumps({"signal_id": signal_id, "evidence": signal.evidence,
                           "sample_events": rows}, default=str)[:20000]

    def _sample_from_entities(self, signal: Signal, n: int) -> list[dict[str, Any]]:
        for entity in signal.entities:
            if entity.type == "ip":
                rows = self.query.sample(n=n, src_ip=entity.value)
                if rows:
                    return rows
                rows = self.query.sample(n=n, client_ip=entity.value)
                if rows:
                    return rows
            elif entity.type == "domain":
                rows = self.query.sample(n=n, domain=entity.value)
                if rows:
                    return rows
        return []

    def enrich_ip(self, args: dict[str, Any]) -> str:
        if over := self._spend("enrich_ip"):
            return over
        ips = [str(x) for x in (args.get("ips") or [])][:MAX_ENRICH_PER_CALL]
        if not ips:
            return "no ips supplied"
        results = self.broker.enrich("ip", ips)
        return json.dumps({
            "results": [r.to_bundle() for r in results],
            "budget": self.broker.budget_report(),
            "reminder": ("Reputation corroborates a classification you already made "
                         "from local behaviour. It cannot create a finding, and "
                         "country is never a severity input."),
        }, default=str)[:15000]

    def enrich_domain(self, args: dict[str, Any]) -> str:
        if over := self._spend("enrich_domain"):
            return over
        domains = [str(x) for x in (args.get("domains") or [])][:MAX_ENRICH_PER_CALL]
        if not domains:
            return "no domains supplied"
        results = self.broker.enrich("domain", domains)
        return json.dumps({
            "results": [r.to_bundle() for r in results],
            "budget": self.broker.budget_report(),
        }, default=str)[:15000]

    def get_entity_history(self, args: dict[str, Any]) -> str:
        if over := self._spend("get_entity_history"):
            return over
        value = str(args.get("value") or "")
        if not value:
            return "no value supplied"
        info = self.store.entity_info(value)
        findings = self.baseline.prior_findings(value, days=90)
        return json.dumps({
            "entity": value,
            "baseline": info or "never observed before this run",
            "prior_findings": findings or "none in the last 90 days",
        }, default=str)[:10000]

    def get_metric_history(self, args: dict[str, Any]) -> str:
        if over := self._spend("get_metric_history"):
            return over
        key = str(args.get("key") or "")
        days = min(int(args.get("days") or 30), 365)
        series = self.baseline.series(key, days=days)
        if not series:
            return f"no history for metric {key!r} in the last {days} days"
        return json.dumps({"key": key, "days": days, "series": series}, default=str)[:10000]

    def get_device_directory(self, args: dict[str, Any]) -> str:
        if over := self._spend("get_device_directory"):
            return over
        ip = str(args.get("ip") or "").strip()
        if ip:
            device = self.devices.get(ip)
            if device is None:
                known = ", ".join(d.ip for d in self.devices.all()[:50])
                return f"no directory entry for {ip!r}. Known IPs: {known or '(none)'}"
            return json.dumps(device.to_dict(), default=str)
        return json.dumps({"devices": self.devices.to_bundle()}, default=str)[:20000]

    def add_notebook_entry(self, args: dict[str, Any]) -> str:
        if over := self._spend("add_notebook_entry"):
            return over
        text = str(args.get("text") or "").strip()
        if not text:
            return "text is required"
        if len(text) > self.notebook_max_entry_chars:
            return (f"entry is {len(text)} characters, over the "
                    f"{self.notebook_max_entry_chars}-character limit "
                    f"(DAWNPATROL_MCP_NOTEBOOK_MAX_ENTRY_CHARS). Split it into "
                    f"more than one entry.")
        self.store.add_notebook_entry(text, author="analysis-agent")
        total = self.store.count_notebook_entries()
        injected = min(total, self.notebook_max_injected)
        result: dict[str, Any] = {
            "stored": True,
            "total_entries": total,
            "injected_into_future_runs": injected,
        }
        if total > self.notebook_max_injected:
            result["note"] = (
                f"There are now {total} notebook entries, but only the most "
                f"recent {self.notebook_max_injected} are injected into any run's "
                f"context (DAWNPATROL_MCP_NOTEBOOK_MAX_INJECTED). The oldest "
                f"{total - self.notebook_max_injected} will not be seen by a "
                f"future run unless that limit is raised or older entries are "
                f"removed via the MCP notebook tools."
            )
        return json.dumps(result, default=str)

    def hunt_history(self, args: dict[str, Any]) -> str:
        if over := self._spend("hunt_history"):
            return over
        domain = args.get("domain")
        ip = args.get("ip")
        days = min(int(args.get("days") or 180), 365)
        if domain:
            rows = self.store.hunt_domain(str(domain), days=days)
            label = f"domain like {domain!r}"
        elif ip:
            rows = self.store.hunt_ip(str(ip), days=days)
            label = f"ip {ip!r}"
        else:
            return "supply either 'domain' or 'ip'"
        if not rows:
            return (f"no record of {label} in the last {days} days of retained "
                    f"history. Note this is limited by retention, not proof of absence.")
        return json.dumps({"query": label, "days": days, "rows": rows}, default=str)[:15000]

    # ----- spec assembly --------------------------------------------------------- #

    def specs(self) -> list[ToolSpec]:
        tools = [
            ToolSpec(
                name="describe_schema",
                description=(
                    "Show the event-store schema, available columns, and example "
                    "queries. Call this before your first query_events."
                ),
                parameters={"type": "object", "properties": {}, "additionalProperties": False},
                handler=self.describe_schema,
            ),
            ToolSpec(
                name="query_events",
                description=(
                    "Run one read-only SELECT against the event store to test a "
                    "hypothesis. Queries on `events` must filter by run_id. Use this "
                    "when a signal raises a question the bundle does not answer."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["sql"],
                    "properties": {
                        "sql": {"type": "string", "description": "A single SELECT statement."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    },
                },
                handler=self.query_events,
            ),
            ToolSpec(
                name="sample_events",
                description=(
                    "Retrieve the raw events behind a signal, so you can quote "
                    "specific evidence rather than paraphrasing an aggregate."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["signal_id"],
                    "properties": {
                        "signal_id": {"type": "string"},
                        "n": {"type": "integer", "minimum": 1, "maximum": 50},
                    },
                },
                handler=self.sample_events,
            ),
            ToolSpec(
                name="get_entity_history",
                description=(
                    "When was this IP or domain first seen on this network, how "
                    "often, and has it been reported before? This is how you tell "
                    "novel from routine."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                },
                handler=self.get_entity_history,
            ),
            ToolSpec(
                name="get_metric_history",
                description="Time series for one metric key, for trend judgements.",
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["key"],
                    "properties": {
                        "key": {"type": "string"},
                        "days": {"type": "integer", "minimum": 1, "maximum": 365},
                    },
                },
                handler=self.get_metric_history,
            ),
            ToolSpec(
                name="hunt_history",
                description=(
                    "Search the long-term retained history for a domain or IP, "
                    "beyond this run's raw events. Use for retrospective questions."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "domain": {"type": "string"},
                        "ip": {"type": "string"},
                        "days": {"type": "integer", "minimum": 1, "maximum": 365},
                    },
                },
                handler=self.hunt_history,
            ),
        ]

        if self.devices:
            tools.append(ToolSpec(
                name="get_device_directory",
                description=(
                    "Full detail for one network device by IP, or every device "
                    "known this run if no IP is given: hostname, hardware, OS, "
                    "uptime, location, which sources reported it and in what role. "
                    "The evidence bundle only shows a one-line summary per device - "
                    "use this when you need the full record."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "ip": {"type": "string",
                              "description": "Omit to list every known device."},
                    },
                },
                handler=self.get_device_directory,
            ))

        if self.notebook_enabled:
            tools.append(ToolSpec(
                name="add_notebook_entry",
                description=(
                    "Leave a short note for a future run - something you learned "
                    "this run that profile.yml doesn't capture and that would "
                    "otherwise be lost when this run ends: a device's real "
                    "identity, a source's quirky logging behaviour, context that "
                    "explains a finding so it isn't re-flagged from scratch. "
                    f"Only the most recent {self.notebook_max_injected} entries "
                    "across the WHOLE notebook (not just yours) are shown to any "
                    "run - adding one past that limit pushes the single oldest "
                    "entry out of every future run's context, silently. Do not "
                    "use this to restate something already in profile.yml or in "
                    "this run's findings; write to it sparingly. You can add, but "
                    "not delete - removing a stale note requires the MCP "
                    "notebook tools."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text"],
                    "properties": {
                        "text": {"type": "string",
                                "maxLength": self.notebook_max_entry_chars},
                    },
                },
                handler=self.add_notebook_entry,
            ))

        if self.broker.available_for("ip"):
            tools.append(ToolSpec(
                name="enrich_ip",
                description=(
                    "Reputation for public IPs. Classify behaviourally FIRST, then "
                    "enrich to corroborate. Budgeted per run and cached; spend it on "
                    "sustained probers, block candidates, and unexpected egress "
                    "destinations - not on members of a scanner sweep."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ips"],
                    "properties": {
                        "ips": {"type": "array", "items": {"type": "string"},
                                "maxItems": MAX_ENRICH_PER_CALL},
                    },
                },
                handler=self.enrich_ip,
            ))

        if self.broker.available_for("domain"):
            tools.append(ToolSpec(
                name="enrich_domain",
                description=(
                    "Reputation for domains. Use on novel or DGA-shaped domains tied "
                    "to a candidate finding. Do not spend it on well-known domains."
                ),
                parameters={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["domains"],
                    "properties": {
                        "domains": {"type": "array", "items": {"type": "string"},
                                    "maxItems": MAX_ENRICH_PER_CALL},
                    },
                },
                handler=self.enrich_domain,
            ))

        tools.append(ToolSpec(
            name=SUBMIT_TOOL,
            description=(
                "Submit the completed analysis. Call this exactly once, when you are "
                "done investigating. This ends the run."
            ),
            parameters=ANALYSIS_SCHEMA,
            handler=lambda args: args,
            terminal=True,
        ))
        return tools
