"""Persistence layer.

SQLite by default, MySQL when credentials are supplied. All access goes through
SQLAlchemy Core so the dialect is a configuration detail rather than a code path.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import create_engine, delete, event, func, insert, select, text, update
from sqlalchemy.engine import Engine

from . import schema as S
from .config import DatabaseSettings, RetentionSettings
from .models import (
    UTC,
    CanaryResult,
    DeliveryResult,
    Entity,
    EntityType,
    Event,
    EventKind,
    Finding,
    Metric,
    Severity,
    Signal,
    SourceHealth,
    Window,
)

log = logging.getLogger(__name__)

EVENT_COLUMNS = (
    "src_ip", "dst_ip", "src_port", "dst_port", "proto", "action", "iface_in",
    "iface_out", "ttl", "pkt_len", "domain", "qtype", "blocked", "block_reason",
    "upstream", "client_ip", "device", "program", "severity", "message", "user",
    "src_zone", "dst_zone",
)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; normalize everything to aware UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


class Store:
    """Owns the engine and every write. Read-heavy analysis goes through EventQuery."""

    def __init__(self, settings: DatabaseSettings, retention: RetentionSettings | None = None) -> None:
        self.settings = settings
        self.retention = retention or RetentionSettings()
        kwargs: dict[str, Any] = {"echo": settings.echo, "future": True}
        if settings.is_mysql:
            kwargs.update(pool_size=settings.pool_size, pool_pre_ping=True, pool_recycle=3600)
        self.engine: Engine = create_engine(settings.url, **kwargs)
        if not settings.is_mysql:
            self._tune_sqlite()

    def _tune_sqlite(self) -> None:
        """Applied on every pooled connection, not just the one that opens first.

        The MCP server and the scheduler each pull connections from the same
        pool concurrently. A one-shot ``PRAGMA`` run at startup only ever
        configures whichever single DBAPI connection happened to be open at
        that moment - every other connection the pool hands out afterward
        reverts to SQLite's own defaults, in particular ``busy_timeout=0``,
        which turns an ordinary write held during a large batch insert (a
        180k-event PERSIST stage, say) into an immediate "database is locked"
        for anything else trying to write at the same time, rather than a
        short, harmless wait. Verified against a real deployment: the MCP
        server's own write path hit exactly this before this fix.
        """

        @event.listens_for(self.engine, "connect")
        def _set_pragma(dbapi_conn: Any, _record: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

        # Force the listener to fire once now too, so callers that only ever
        # use a single connection (the common case) don't wait on the first
        # real query to discover misconfiguration.
        with self.engine.connect():
            pass

    def create_all(self) -> None:
        S.metadata.create_all(self.engine)

    def dispose(self) -> None:
        self.engine.dispose()

    # ----- runs ------------------------------------------------------------ #

    def next_run_number(self) -> int:
        with self.engine.connect() as conn:
            n = conn.execute(select(func.count()).select_from(S.runs)).scalar_one()
        return int(n) + 1

    def start_run(self, run_id: str, run_number: int, started_at: datetime, window: Window) -> None:
        with self.engine.begin() as conn:
            conn.execute(insert(S.runs).values(
                run_id=run_id, run_number=run_number, started_at=started_at,
                window_start=window.start, window_end=window.end,
                window_hours=window.hours,
            ))

    def finish_run(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        if "stages" in fields:
            fields["stages_json"] = json.dumps(fields.pop("stages"))
        with self.engine.begin() as conn:
            conn.execute(update(S.runs).where(S.runs.c.run_id == run_id).values(**fields))

    def recent_runs(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.runs).order_by(S.runs.c.started_at.desc()).limit(limit)
            ).mappings().all()
        return [dict(r) for r in rows]

    def last_successful_run(self, before_run_id: str | None = None) -> dict[str, Any] | None:
        stmt = select(S.runs).where(S.runs.c.finished_at.is_not(None))
        if before_run_id:
            stmt = stmt.where(S.runs.c.run_id != before_run_id)
        stmt = stmt.order_by(S.runs.c.started_at.desc()).limit(1)
        with self.engine.connect() as conn:
            row = conn.execute(stmt).mappings().first()
        return dict(row) if row else None

    # ----- events ---------------------------------------------------------- #

    def insert_events(self, run_id: str, events: Iterable[Event], batch: int = 1000) -> int:
        rows: list[dict[str, Any]] = []
        total = 0
        with self.engine.begin() as conn:
            for ev in events:
                row: dict[str, Any] = {
                    "run_id": run_id,
                    "ts": ev.ts,
                    "source": ev.source,
                    "kind": str(ev.kind),
                    "dedup_key": ev.dedup_key,
                    "raw_json": json.dumps(ev.raw, default=str) if ev.raw else None,
                }
                for col in EVENT_COLUMNS:
                    row[col] = getattr(ev, col)
                rows.append(row)
                if len(rows) >= batch:
                    conn.execute(insert(S.events), rows)
                    total += len(rows)
                    rows = []
            if rows:
                conn.execute(insert(S.events), rows)
                total += len(rows)
        return total

    def event_count(self, run_id: str) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(
                select(func.count()).select_from(S.events).where(S.events.c.run_id == run_id)
            ).scalar_one())

    # ----- health, metrics, signals, findings ------------------------------ #

    def save_health(self, run_id: str, health: Sequence[SourceHealth]) -> None:
        if not health:
            return
        with self.engine.begin() as conn:
            conn.execute(insert(S.source_health), [
                {
                    "run_id": run_id, "source": h.source, "state": str(h.state),
                    "records": h.records, "unique_records": h.unique_records,
                    "reported_total": h.reported_total, "span_hours": h.span_hours,
                    "requested_hours": h.requested_hours, "pages": h.pages,
                    "probes_json": json.dumps([p.to_dict() for p in h.probes]),
                    "notes_json": json.dumps(h.notes),
                }
                for h in health
            ])

    def save_metrics(self, run_id: str, ts: datetime, metrics: Sequence[Metric]) -> None:
        if not metrics:
            return
        rows = []
        for m in metrics:
            numeric = isinstance(m.value, (int, float)) and not isinstance(m.value, bool)
            rows.append({
                "run_id": run_id, "ts": ts, "key": m.key,
                "value_num": float(m.value) if numeric else None,
                "value_text": None if numeric else str(m.value),
                "unit": m.unit, "section": m.section,
            })
        with self.engine.begin() as conn:
            conn.execute(insert(S.metrics), rows)

    def metric_history(self, key: str, days: int = 30) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(days=days)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.metrics.c.ts, S.metrics.c.value_num, S.metrics.c.value_text)
                .where(S.metrics.c.key == key, S.metrics.c.ts >= since)
                .order_by(S.metrics.c.ts.asc())
            ).mappings().all()
        return [
            {"ts": _aware(r["ts"]).isoformat(), "value": r["value_num"] if r["value_num"] is not None else r["value_text"]}
            for r in rows
        ]

    def prior_metric_values(self, run_id: str | None) -> dict[str, float]:
        """Numeric metrics from the most recent completed run before ``run_id``."""
        prior = self.last_successful_run(before_run_id=run_id)
        if not prior:
            return {}
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.metrics.c.key, S.metrics.c.value_num)
                .where(S.metrics.c.run_id == prior["run_id"], S.metrics.c.value_num.is_not(None))
            ).all()
        return {k: float(v) for k, v in rows}

    def save_signals(self, run_id: str, signals: Sequence[Signal]) -> None:
        if not signals:
            return
        with self.engine.begin() as conn:
            conn.execute(insert(S.signals), [
                {
                    "run_id": run_id, "signal_id": s.id, "analyzer": s.analyzer,
                    "title": s.title, "taxonomy": s.taxonomy,
                    "severity_hint": int(s.severity_hint), "confidence": s.confidence,
                    "entities_json": json.dumps([e.to_dict() for e in s.entities]),
                    "evidence_json": json.dumps(s.evidence, default=str),
                    "is_canary": s.is_canary,
                }
                for s in signals
            ])

    def save_findings(self, run_id: str, ts: datetime, findings: Sequence[Finding]) -> None:
        if not findings:
            return
        with self.engine.begin() as conn:
            conn.execute(insert(S.findings), [
                {
                    "run_id": run_id, "finding_id": f.id, "ts": ts, "title": f.title,
                    "severity": int(f.severity), "confidence": str(f.confidence),
                    "taxonomy": f.taxonomy, "zone": f.zone, "what": f.what, "why": f.why,
                    "not_this": f.not_this, "action": f.action,
                    "signal_ids_json": json.dumps(f.signal_ids),
                    "evidence_kinds_json": json.dumps(f.evidence_kinds),
                    "entities_json": json.dumps([e.to_dict() for e in f.entities]),
                    "suppressed": f.suppressed, "suppressed_reason": f.suppressed_reason,
                }
                for f in findings
            ])

    def finding_recurrence(self, taxonomy: str, entity_value: str | None = None,
                           days: int = 30) -> int:
        """Distinct prior runs that produced this taxonomy (optionally for an entity)."""
        since = datetime.now(UTC) - timedelta(days=days)
        stmt = select(func.count(func.distinct(S.findings.c.run_id))).where(
            S.findings.c.taxonomy == taxonomy, S.findings.c.ts >= since
        )
        if entity_value:
            stmt = stmt.where(S.findings.c.entities_json.like(f'%"{entity_value}"%'))
        with self.engine.connect() as conn:
            return int(conn.execute(stmt).scalar_one() or 0)

    def prior_findings_for(self, entity_value: str, days: int = 90) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(days=days)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.findings.c.ts, S.findings.c.title, S.findings.c.severity,
                       S.findings.c.taxonomy, S.findings.c.run_id)
                .where(S.findings.c.ts >= since,
                       S.findings.c.entities_json.like(f'%"{entity_value}"%'))
                .order_by(S.findings.c.ts.desc()).limit(25)
            ).mappings().all()
        return [
            {"ts": _aware(r["ts"]).isoformat(), "title": r["title"],
             "severity": Severity(r["severity"]).label(), "taxonomy": r["taxonomy"]}
            for r in rows
        ]

    # ----- entity baseline -------------------------------------------------- #

    def observe_entities(self, pairs: Iterable[tuple[EntityType, str, int]],
                         now: datetime) -> None:
        """Upsert first_seen / last_seen / occurrence counts.

        Deliberately not a dialect-specific UPSERT: the volume here is small
        (thousands of distinct entities, not millions of events) and portability
        across SQLite and MySQL matters more than the last few milliseconds.
        """
        items = [(str(t), v, c) for t, v, c in pairs if v]
        if not items:
            return
        with self.engine.begin() as conn:
            existing = {}
            for chunk in _chunks(items, 500):
                values = [v for _, v, _ in chunk]
                rows = conn.execute(
                    select(S.entities.c.etype, S.entities.c.value, S.entities.c.occurrences)
                    .where(S.entities.c.value.in_(values))
                ).all()
                for etype, value, occ in rows:
                    existing[(etype, value)] = occ or 0
            fresh, updates = [], []
            for etype, value, count in items:
                if (etype, value) in existing:
                    updates.append((etype, value, existing[(etype, value)] + count))
                else:
                    fresh.append({"etype": etype, "value": value, "first_seen": now,
                                  "last_seen": now, "occurrences": count})
            if fresh:
                conn.execute(insert(S.entities), fresh)
            for etype, value, total in updates:
                conn.execute(
                    update(S.entities)
                    .where(S.entities.c.etype == etype, S.entities.c.value == value)
                    .values(last_seen=now, occurrences=total)
                )

    def entity_first_seen(self, etype: EntityType, values: Sequence[str]) -> dict[str, datetime]:
        if not values:
            return {}
        out: dict[str, datetime] = {}
        with self.engine.connect() as conn:
            for chunk in _chunks(list(values), 500):
                rows = conn.execute(
                    select(S.entities.c.value, S.entities.c.first_seen)
                    .where(S.entities.c.etype == str(etype), S.entities.c.value.in_(chunk))
                ).all()
                for value, first in rows:
                    out[value] = _aware(first)
        return out

    def entity_info(self, value: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(S.entities).where(S.entities.c.value == value).limit(1)
            ).mappings().first()
        if not row:
            return None
        return {
            "type": row["etype"], "value": row["value"],
            "first_seen": _aware(row["first_seen"]).isoformat(),
            "last_seen": _aware(row["last_seen"]).isoformat(),
            "occurrences": row["occurrences"],
        }

    # ----- long-term IOC slices --------------------------------------------- #

    def save_ioc_dns(self, run_id: str, day: datetime,
                     rows: Sequence[tuple[str | None, str, int, int]]) -> None:
        if not rows:
            return
        payload = [
            {"run_id": run_id, "day": day, "client_ip": c, "domain": d,
             "queries": q, "blocked": b}
            for c, d, q, b in rows
        ]
        with self.engine.begin() as conn:
            for chunk in _chunks(payload, 1000):
                conn.execute(insert(S.ioc_dns), chunk)

    def save_ioc_flow(self, run_id: str, day: datetime,
                      rows: Sequence[tuple[str | None, str, int | None, str | None, int]]) -> None:
        if not rows:
            return
        payload = [
            {"run_id": run_id, "day": day, "src_ip": s, "dst_ip": d,
             "dst_port": p, "proto": pr, "hits": h}
            for s, d, p, pr, h in rows
        ]
        with self.engine.begin() as conn:
            for chunk in _chunks(payload, 1000):
                conn.execute(insert(S.ioc_flow), chunk)

    def hunt_domain(self, pattern: str, days: int = 180) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(days=days)
        like = pattern if "%" in pattern else f"%{pattern}%"
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.ioc_dns.c.day, S.ioc_dns.c.client_ip, S.ioc_dns.c.domain,
                       S.ioc_dns.c.queries, S.ioc_dns.c.blocked)
                .where(S.ioc_dns.c.day >= since, S.ioc_dns.c.domain.like(like))
                .order_by(S.ioc_dns.c.day.desc()).limit(500)
            ).mappings().all()
        return [{**dict(r), "day": _aware(r["day"]).strftime("%Y-%m-%d")} for r in rows]

    def hunt_ip(self, ip: str, days: int = 180) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(days=days)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.ioc_flow.c.day, S.ioc_flow.c.src_ip, S.ioc_flow.c.dst_ip,
                       S.ioc_flow.c.dst_port, S.ioc_flow.c.proto, S.ioc_flow.c.hits)
                .where(S.ioc_flow.c.day >= since,
                       (S.ioc_flow.c.dst_ip == ip) | (S.ioc_flow.c.src_ip == ip))
                .order_by(S.ioc_flow.c.day.desc()).limit(500)
            ).mappings().all()
        return [{**dict(r), "day": _aware(r["day"]).strftime("%Y-%m-%d")} for r in rows]

    # ----- enrichment cache -------------------------------------------------- #

    def cache_get(self, enricher: str, subject: str) -> dict[str, Any] | None:
        now = datetime.now(UTC)
        with self.engine.connect() as conn:
            row = conn.execute(
                select(S.enrichment_cache.c.payload_json, S.enrichment_cache.c.expires_at)
                .where(S.enrichment_cache.c.enricher == enricher,
                       S.enrichment_cache.c.subject == subject)
            ).mappings().first()
        if not row:
            return None
        if _aware(row["expires_at"]) < now:
            return None
        try:
            return json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None

    def cache_put(self, enricher: str, subject: str, payload: dict[str, Any],
                  ttl: timedelta) -> None:
        now = datetime.now(UTC)
        with self.engine.begin() as conn:
            conn.execute(delete(S.enrichment_cache).where(
                S.enrichment_cache.c.enricher == enricher,
                S.enrichment_cache.c.subject == subject,
            ))
            conn.execute(insert(S.enrichment_cache).values(
                enricher=enricher, subject=subject, fetched_at=now,
                expires_at=now + ttl, payload_json=json.dumps(payload, default=str),
            ))

    # ----- watchlist and suppressions ---------------------------------------- #

    def add_watch(self, entity_type: str, entity_value: str, reason: str,
                  run_id: str, expires_days: int = 7) -> None:
        now = datetime.now(UTC)
        with self.engine.begin() as conn:
            conn.execute(delete(S.watchlist).where(
                S.watchlist.c.entity_type == entity_type,
                S.watchlist.c.entity_value == entity_value,
            ))
            conn.execute(insert(S.watchlist).values(
                entity_type=entity_type, entity_value=entity_value, reason=reason,
                created_run=run_id, created_at=now,
                expires_at=now + timedelta(days=max(1, expires_days)),
            ))

    def active_watchlist(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.watchlist).where(
                    (S.watchlist.c.expires_at.is_(None)) | (S.watchlist.c.expires_at >= now)
                ).order_by(S.watchlist.c.created_at.desc())
            ).mappings().all()
        return [
            {"type": r["entity_type"], "value": r["entity_value"], "reason": r["reason"],
             "expires": _aware(r["expires_at"]).strftime("%Y-%m-%d") if r["expires_at"] else "never"}
            for r in rows
        ]

    def add_suppression(self, matcher: dict[str, Any], reason: str, author: str,
                        expires_days: int | None = 90) -> int:
        now = datetime.now(UTC)
        expires = now + timedelta(days=expires_days) if expires_days else None
        with self.engine.begin() as conn:
            result = conn.execute(insert(S.suppressions).values(
                matcher_json=json.dumps(matcher), reason=reason, author=author,
                created_at=now, expires_at=expires,
            ))
        return int(result.inserted_primary_key[0])

    def active_suppressions(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.suppressions).where(
                    (S.suppressions.c.expires_at.is_(None)) | (S.suppressions.c.expires_at >= now)
                )
            ).mappings().all()
        out = []
        for r in rows:
            try:
                matcher = json.loads(r["matcher_json"])
            except json.JSONDecodeError:
                continue
            out.append({
                "id": r["id"], "matcher": matcher, "reason": r["reason"],
                "author": r["author"],
                "expires": _aware(r["expires_at"]).strftime("%Y-%m-%d") if r["expires_at"] else "never",
            })
        return out

    def bump_suppression(self, suppression_id: int) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                update(S.suppressions).where(S.suppressions.c.id == suppression_id)
                .values(hits=S.suppressions.c.hits + 1)
            )

    def delete_suppression(self, suppression_id: int) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                delete(S.suppressions).where(S.suppressions.c.id == suppression_id)
            )
        return result.rowcount > 0

    # ----- agent notebook ---------------------------------------------------- #
    # Off by default (DAWNPATROL_MCP_NOTEBOOK_ENABLED); written only by an
    # external agent over MCP, read back by the harness alongside profile.yml.

    def add_notebook_entry(self, text: str, author: str = "") -> int:
        with self.engine.begin() as conn:
            result = conn.execute(insert(S.notebook).values(
                created_at=datetime.now(UTC), author=author, text=text,
            ))
        return int(result.inserted_primary_key[0])

    def list_notebook_entries(self, limit: int = 500) -> list[dict[str, Any]]:
        """Oldest first - a notebook reads top to bottom, like a log."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.notebook)
                .order_by(S.notebook.c.created_at.asc(), S.notebook.c.id.asc())
                .limit(limit)
            ).mappings().all()
        return [
            {"id": r["id"], "created_at": _aware(r["created_at"]).isoformat(),
             "author": r["author"] or "", "text": r["text"]}
            for r in rows
        ]

    def recent_notebook_entries(self, limit: int) -> list[dict[str, Any]]:
        """The most recent ``limit`` entries, oldest of that set first.

        Used to bound how much notebook content is injected into a run's
        prompt - unlike :meth:`list_notebook_entries`, which is for reading
        the full history and should never silently drop the oldest entries.
        """
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(S.notebook)
                .order_by(S.notebook.c.created_at.desc(), S.notebook.c.id.desc())
                .limit(limit)
            ).mappings().all()
        rows = list(reversed(rows))
        return [
            {"id": r["id"], "created_at": _aware(r["created_at"]).isoformat(),
             "author": r["author"] or "", "text": r["text"]}
            for r in rows
        ]

    def delete_notebook_entry(self, entry_id: int) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(delete(S.notebook).where(S.notebook.c.id == entry_id))
        return result.rowcount > 0

    # ----- canaries and deliveries -------------------------------------------- #

    def save_canaries(self, run_id: str, results: Sequence[CanaryResult]) -> None:
        if not results:
            return
        with self.engine.begin() as conn:
            conn.execute(insert(S.canaries), [
                {"run_id": run_id, "canary": c.name, "detected": c.detected, "detail": c.detail}
                for c in results
            ])

    def save_deliveries(self, run_id: str, results: Sequence[DeliveryResult]) -> None:
        if not results:
            return
        now = datetime.now(UTC)
        with self.engine.begin() as conn:
            conn.execute(insert(S.deliveries), [
                {"run_id": run_id, "output": d.output, "ok": d.ok,
                 "skipped": d.skipped, "detail": d.detail, "at": now}
                for d in results
            ])

    # ----- retention ----------------------------------------------------------- #

    def purge(self) -> dict[str, int]:
        """Age out raw events; keep the narrow long-term slices."""
        now = datetime.now(UTC)
        raw_cutoff = now - timedelta(days=self.retention.raw_days)
        deleted: dict[str, int] = {}
        with self.engine.begin() as conn:
            old_runs = [
                r[0] for r in conn.execute(
                    select(S.runs.c.run_id).where(S.runs.c.started_at < raw_cutoff)
                ).all()
            ]
            if old_runs:
                for chunk in _chunks(old_runs, 200):
                    res = conn.execute(delete(S.events).where(S.events.c.run_id.in_(chunk)))
                    deleted["events"] = deleted.get("events", 0) + res.rowcount
            for table, days in (
                (S.ioc_dns, self.retention.ioc_days),
                (S.ioc_flow, self.retention.ioc_days),
            ):
                res = conn.execute(delete(table).where(table.c.day < now - timedelta(days=days)))
                deleted[table.name] = res.rowcount
            res = conn.execute(delete(S.metrics).where(
                S.metrics.c.ts < now - timedelta(days=self.retention.metrics_days)))
            deleted["metrics"] = res.rowcount
            res = conn.execute(delete(S.enrichment_cache).where(
                S.enrichment_cache.c.expires_at < now))
            deleted["enrichment_cache"] = res.rowcount
            res = conn.execute(delete(S.watchlist).where(
                S.watchlist.c.expires_at.is_not(None), S.watchlist.c.expires_at < now))
            deleted["watchlist"] = res.rowcount
        return {k: v for k, v in deleted.items() if v}

    # ----- read-only SQL for the agent -------------------------------------- #

    def readonly_sql(self, sql: str, max_rows: int = 200) -> tuple[list[str], list[list[Any]]]:
        """Execute a pre-validated SELECT. Validation lives in agent.sqlguard."""
        with self.engine.connect() as conn:
            if self.settings.is_mysql:
                conn.execute(text("SET SESSION TRANSACTION READ ONLY"))
            result = conn.execute(text(sql))
            columns = list(result.keys())
            rows = [list(r) for r in result.fetchmany(max_rows)]
        return columns, rows


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def entity_pairs_from_events(events: Iterable[Event]) -> list[tuple[EntityType, str, int]]:
    """Collapse a run's events into entity occurrence counts for the baseline."""
    counts: dict[tuple[EntityType, str], int] = {}

    def bump(etype: EntityType, value: str | None) -> None:
        if value:
            counts[(etype, value)] = counts.get((etype, value), 0) + 1

    for ev in events:
        if ev.kind == EventKind.DNS:
            bump(EntityType.DOMAIN, (ev.domain or "").lower() or None)
            bump(EntityType.IP, ev.client_ip)
        else:
            bump(EntityType.IP, ev.src_ip)
        # `user` carries a MAC address on DHCP lease lines and Wi-Fi
        # deauthentication events (see librenms_syslog.py) - a device
        # identity that survives DHCP lease renewal, unlike its IP.
        bump(EntityType.DEVICE, ev.user)
    return [(t, v, c) for (t, v), c in counts.items()]


def make_entity(etype: EntityType, value: str, role: str = "") -> Entity:
    return Entity(type=etype, value=value, role=role)
