"""Database schema. One logical database, two lifetimes.

Raw ``events`` age out on a short retention; the narrow ``ioc_dns`` / ``ioc_flow``
slices and ``metrics`` persist for long-horizon trending and retrospective
hunting. Identical DDL on SQLite and MySQL - the only dialect concession is
string length, which MySQL requires for indexed columns.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()

#: SQLite only autoincrements an INTEGER PRIMARY KEY (the rowid alias); a
#: BIGINT column silently loses autoincrement and every insert fails on NOT NULL.
#: MySQL keeps BIGINT, where the wider range actually matters.
PK = BigInteger().with_variant(Integer, "sqlite")

# MySQL cannot index unbounded TEXT, so every indexed string is bounded.
_ID = 64
_IP = 45          # INET6_ADDRSTRLEN
_NAME = 255
_SHORT = 128

runs = Table(
    "runs", metadata,
    Column("run_id", String(_ID), primary_key=True),
    Column("run_number", Integer, nullable=False, default=1),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True)),
    Column("window_start", DateTime(timezone=True), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False),
    Column("window_hours", Float, nullable=False, default=0.0),
    Column("status", String(16), default="GREEN"),
    Column("finding_count", Integer, default=0),
    Column("degraded", Boolean, default=False),
    Column("model", String(_NAME)),
    Column("provider", String(_SHORT)),
    Column("input_tokens", Integer, default=0),
    Column("output_tokens", Integer, default=0),
    Column("cache_read_tokens", Integer, default=0),
    Column("cost_usd", Float, default=0.0),
    Column("error", Text),
    Column("stages_json", Text),
    Index("ix_runs_started", "started_at"),
)

source_health = Table(
    "source_health", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("source", String(_SHORT), nullable=False),
    Column("state", String(16), nullable=False),
    Column("records", Integer, default=0),
    Column("unique_records", Integer, default=0),
    Column("reported_total", Integer),
    Column("span_hours", Float, default=0.0),
    Column("requested_hours", Float, default=0.0),
    Column("pages", Integer, default=0),
    Column("probes_json", Text),
    Column("notes_json", Text),
    Index("ix_health_run", "run_id"),
)

events = Table(
    "events", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("source", String(_SHORT), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("dedup_key", String(_NAME), nullable=False),
    Column("src_ip", String(_IP)),
    Column("dst_ip", String(_IP)),
    Column("src_port", Integer),
    Column("dst_port", Integer),
    Column("proto", String(16)),
    Column("action", String(16)),
    Column("iface_in", String(32)),
    Column("iface_out", String(32)),
    Column("ttl", Integer),
    Column("pkt_len", Integer),
    Column("domain", String(_NAME)),
    Column("qtype", String(16)),
    Column("blocked", Boolean),
    Column("block_reason", String(64)),
    Column("upstream", String(_NAME)),
    Column("client_ip", String(_IP)),
    Column("device", String(_NAME)),
    Column("program", String(_SHORT)),
    Column("severity", String(16)),
    Column("message", Text),
    Column("user", String(_NAME)),
    Column("src_zone", String(_SHORT)),
    Column("dst_zone", String(_SHORT)),
    Column("raw_json", Text),
    Index("ix_events_run_ts", "run_id", "ts"),
    Index("ix_events_run_kind", "run_id", "kind"),
    Index("ix_events_src", "run_id", "src_ip"),
    Index("ix_events_dst_port", "run_id", "dst_port"),
    Index("ix_events_domain", "run_id", "domain"),
    Index("ix_events_client", "run_id", "client_ip"),
    Index("ix_events_dedup", "run_id", "dedup_key"),
)

metrics = Table(
    "metrics", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("key", String(_NAME), nullable=False),
    Column("value_num", Float),
    Column("value_text", Text),
    Column("unit", String(32)),
    Column("section", String(_SHORT)),
    Index("ix_metrics_key_ts", "key", "ts"),
    Index("ix_metrics_run", "run_id"),
)

signals = Table(
    "signals", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("signal_id", String(_NAME), nullable=False),
    Column("analyzer", String(_SHORT), nullable=False),
    Column("title", Text),
    Column("taxonomy", String(_NAME)),
    Column("severity_hint", Integer, default=0),
    Column("confidence", Float, default=0.0),
    Column("entities_json", Text),
    Column("evidence_json", Text),
    Column("is_canary", Boolean, default=False),
    Index("ix_signals_run", "run_id"),
    Index("ix_signals_sid", "signal_id"),
)

findings = Table(
    "findings", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("finding_id", String(_NAME), nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("title", Text),
    Column("severity", Integer, default=0),
    Column("confidence", String(16)),
    Column("taxonomy", String(_NAME)),
    Column("zone", String(_SHORT)),
    Column("what", Text),
    Column("why", Text),
    Column("not_this", Text),
    Column("action", Text),
    Column("signal_ids_json", Text),
    Column("evidence_kinds_json", Text),
    Column("entities_json", Text),
    Column("suppressed", Boolean, default=False),
    Column("suppressed_reason", Text),
    Index("ix_findings_run", "run_id"),
    Index("ix_findings_tax", "taxonomy"),
)

entities = Table(
    "entities", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("etype", String(16), nullable=False),
    Column("value", String(_NAME), nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("occurrences", BigInteger, default=0),
    UniqueConstraint("etype", "value", name="uq_entity"),
    Index("ix_entities_lookup", "etype", "value"),
)

ioc_dns = Table(
    "ioc_dns", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("day", DateTime(timezone=True), nullable=False),
    Column("client_ip", String(_IP)),
    Column("domain", String(_NAME), nullable=False),
    Column("queries", Integer, default=0),
    Column("blocked", Integer, default=0),
    Index("ix_iocdns_domain", "domain"),
    Index("ix_iocdns_day", "day"),
)

ioc_flow = Table(
    "ioc_flow", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("day", DateTime(timezone=True), nullable=False),
    Column("src_ip", String(_IP)),
    Column("dst_ip", String(_IP), nullable=False),
    Column("dst_port", Integer),
    Column("proto", String(16)),
    Column("hits", Integer, default=0),
    Index("ix_iocflow_dst", "dst_ip"),
    Index("ix_iocflow_day", "day"),
)

enrichment_cache = Table(
    "enrichment_cache", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("enricher", String(_SHORT), nullable=False),
    Column("subject", String(_NAME), nullable=False),
    Column("fetched_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("payload_json", Text, nullable=False),
    UniqueConstraint("enricher", "subject", name="uq_enrichment"),
    Index("ix_enrich_lookup", "enricher", "subject"),
)

watchlist = Table(
    "watchlist", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("entity_type", String(16), nullable=False),
    Column("entity_value", String(_NAME), nullable=False),
    Column("reason", Text),
    Column("created_run", String(_ID)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True)),
    Index("ix_watch_entity", "entity_type", "entity_value"),
)

suppressions = Table(
    "suppressions", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("matcher_json", Text, nullable=False),
    Column("reason", Text),
    Column("author", String(_NAME)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True)),
    Column("hits", Integer, default=0),
)

canaries = Table(
    "canaries", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("canary", String(_SHORT), nullable=False),
    Column("detected", Boolean, default=False),
    Column("detail", Text),
    Index("ix_canaries_run", "run_id"),
)

#: Free-text context an external agent submits over MCP, read back on every
#: future run alongside profile.yml - see mcpserver/tools.py and agent/harness.py.
#: Off by default (DAWNPATROL_MCP_NOTEBOOK_ENABLED); never touched by the
#: scheduled pipeline itself, only by an operator-authorized external agent.
notebook = Table(
    "notebook", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("author", String(_NAME), default=""),
    Column("text", Text, nullable=False),
    Index("ix_notebook_created", "created_at"),
)

deliveries = Table(
    "deliveries", metadata,
    Column("id", PK, primary_key=True, autoincrement=True),
    Column("run_id", String(_ID), nullable=False),
    Column("output", String(_SHORT), nullable=False),
    Column("ok", Boolean, default=False),
    Column("skipped", Boolean, default=False),
    Column("detail", Text),
    Column("at", DateTime(timezone=True), nullable=False),
    Index("ix_deliveries_run", "run_id"),
)

#: Tables the agent's read-only SQL tool may touch. Everything else - config,
#: deliveries, enrichment payloads - is out of reach.
AGENT_READABLE = frozenset({"events", "metrics", "signals", "ioc_dns", "ioc_flow", "entities"})
