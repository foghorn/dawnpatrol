"""Typed query helpers over a run's events.

Analyzers use this instead of raw SQL so they stay short, readable, and portable
across SQLite and MySQL. Every method is scoped to one run_id.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Integer, and_, case, cast, func, select

from . import schema as S
from .models import UTC, EventKind
from .store import Store, _aware


class EventQuery:
    """Read-side API for analyzers. Immutable, cheap to construct.

    A query can be scoped to, or away from, particular sources. That is how
    canary events stay out of the reported statistics while still being visible
    to a second verification pass: real analysis runs on a query that excludes
    them, and detection is proven on a query that contains only them.
    """

    def __init__(self, store: Store, run_id: str, *,
                 exclude_sources: set[str] | None = None,
                 only_sources: set[str] | None = None) -> None:
        self.store = store
        self.run_id = run_id
        self.exclude_sources = exclude_sources or set()
        self.only_sources = only_sources or set()
        self._engine = store.engine

    # ----- predicates ------------------------------------------------------- #

    def _base(self, **filters: Any):
        clauses = [S.events.c.run_id == self.run_id]
        if self.only_sources:
            clauses.append(S.events.c.source.in_(sorted(self.only_sources)))
        if self.exclude_sources:
            clauses.append(S.events.c.source.notin_(sorted(self.exclude_sources)))
        for key, value in filters.items():
            if value is None:
                continue
            col = getattr(S.events.c, key, None)
            if col is None:
                raise KeyError(f"unknown event column {key!r}")
            if isinstance(value, (list, tuple, set)):
                clauses.append(col.in_(list(value)))
            else:
                if key == "kind":
                    value = str(value)
                clauses.append(col == value)
        return and_(*clauses)

    # ----- scalars ---------------------------------------------------------- #

    def count(self, **filters: Any) -> int:
        with self._engine.connect() as conn:
            return int(conn.execute(
                select(func.count()).select_from(S.events).where(self._base(**filters))
            ).scalar_one())

    def distinct_count(self, column: str, **filters: Any) -> int:
        col = getattr(S.events.c, column)
        with self._engine.connect() as conn:
            return int(conn.execute(
                select(func.count(func.distinct(col)))
                .where(self._base(**filters), col.is_not(None))
            ).scalar_one())

    def kinds_present(self) -> set[EventKind]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(func.distinct(S.events.c.kind)).where(self._base())
            ).all()
        out = set()
        for (k,) in rows:
            try:
                out.add(EventKind(k))
            except ValueError:
                continue
        return out

    def sources_present(self) -> set[str]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(func.distinct(S.events.c.source)).where(self._base())
            ).all()
        return {r[0] for r in rows}

    def time_bounds(self, **filters: Any) -> tuple[datetime | None, datetime | None]:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(func.min(S.events.c.ts), func.max(S.events.c.ts))
                .where(self._base(**filters))
            ).first()
        if not row or row[0] is None:
            return None, None
        return _aware(row[0]), _aware(row[1])

    # ----- groupings -------------------------------------------------------- #

    def top(self, column: str, n: int = 15, *, by: str = "count",
            **filters: Any) -> list[tuple[Any, int]]:
        """Top ``n`` values of ``column``.

        ``by="count"`` ranks by raw hit count; ``by="unique:<other>"`` ranks by
        distinct values of another column - the difference between "one host hit
        this port a lot" and "many hosts probed this port", which is the more
        interesting signal.
        """
        col = getattr(S.events.c, column)
        if by.startswith("unique:"):
            other = getattr(S.events.c, by.split(":", 1)[1])
            measure = func.count(func.distinct(other))
        else:
            measure = func.count()
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(col, measure.label("n"))
                .where(self._base(**filters), col.is_not(None))
                .group_by(col).order_by(func.count().desc() if by == "count" else measure.desc())
                .limit(n)
            ).all()
        return [(r[0], int(r[1])) for r in rows]

    def group_pairs(self, col_a: str, col_b: str, n: int = 20,
                    **filters: Any) -> list[tuple[Any, Any, int]]:
        a, b = getattr(S.events.c, col_a), getattr(S.events.c, col_b)
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(a, b, func.count().label("n"))
                .where(self._base(**filters), a.is_not(None))
                .group_by(a, b).order_by(func.count().desc()).limit(n)
            ).all()
        return [(r[0], r[1], int(r[2])) for r in rows]

    def hourly(self, **filters: Any) -> dict[str, int]:
        """Event counts bucketed by hour. Portable across both dialects."""
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.ts).where(self._base(**filters))
            ).all()
        buckets: dict[str, int] = {}
        for (ts,) in rows:
            key = _aware(ts).strftime("%Y-%m-%d %H:00")
            buckets[key] = buckets.get(key, 0) + 1
        return dict(sorted(buckets.items()))

    def timestamps_for(self, limit: int = 20000, **filters: Any) -> list[datetime]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.ts).where(self._base(**filters))
                .order_by(S.events.c.ts.asc()).limit(limit)
            ).all()
        return [_aware(r[0]) for r in rows]

    def distinct_values(self, column: str, limit: int = 5000, **filters: Any) -> list[Any]:
        col = getattr(S.events.c, column)
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(func.distinct(col))
                .where(self._base(**filters), col.is_not(None)).limit(limit)
            ).all()
        return [r[0] for r in rows]

    def sample(self, n: int = 20, **filters: Any) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events).where(self._base(**filters))
                .order_by(S.events.c.ts.desc()).limit(n)
            ).mappings().all()
        out = []
        for r in rows:
            d = {k: v for k, v in dict(r).items() if v is not None and k not in ("raw_json", "id")}
            if isinstance(d.get("ts"), datetime):
                d["ts"] = _aware(d["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            out.append(d)
        return out

    def sample_by_dedup(self, keys: Sequence[str], n: int = 20) -> list[dict[str, Any]]:
        if not keys:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events)
                .where(self._base(), S.events.c.dedup_key.in_(list(keys)[:200]))
                .limit(n)
            ).mappings().all()
        out = []
        for r in rows:
            d = {k: v for k, v in dict(r).items() if v is not None and k not in ("raw_json", "id")}
            if isinstance(d.get("ts"), datetime):
                d["ts"] = _aware(d["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            out.append(d)
        return out

    # ----- DNS-specific helpers ---------------------------------------------- #

    def dns_domain_stats(self, n: int = 50, blocked: bool | None = None
                         ) -> list[tuple[str, int, int]]:
        """(domain, total_queries, blocked_queries) ordered by total."""
        blocked_expr = func.sum(
            case((S.events.c.blocked.is_(True), 1), else_=0)
        ).label("blocked_n")
        clauses = [self._base(kind=EventKind.DNS), S.events.c.domain.is_not(None)]
        if blocked is not None:
            clauses.append(S.events.c.blocked.is_(blocked))
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.domain, func.count().label("n"), blocked_expr)
                .where(and_(*clauses))
                .group_by(S.events.c.domain)
                .order_by(func.count().desc()).limit(n)
            ).all()
        return [(r[0], int(r[1]), int(r[2] or 0)) for r in rows]

    def dns_client_stats(self, n: int = 30) -> list[tuple[str, int, int]]:
        blocked_expr = func.sum(
            case((S.events.c.blocked.is_(True), 1), else_=0)
        ).label("blocked_n")
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.client_ip, func.count().label("n"), blocked_expr)
                .where(self._base(kind=EventKind.DNS), S.events.c.client_ip.is_not(None))
                .group_by(S.events.c.client_ip)
                .order_by(func.count().desc()).limit(n)
            ).all()
        return [(r[0], int(r[1]), int(r[2] or 0)) for r in rows]

    def dns_pairs_for_ioc(self, limit: int = 50000) -> list[tuple[str | None, str, int, int]]:
        """(client_ip, domain, queries, blocked) for the long-term IOC slice."""
        blocked_expr = func.sum(case((S.events.c.blocked.is_(True), 1), else_=0))
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.client_ip, S.events.c.domain,
                       func.count().label("n"), blocked_expr)
                .where(self._base(kind=EventKind.DNS), S.events.c.domain.is_not(None))
                .group_by(S.events.c.client_ip, S.events.c.domain)
                .order_by(func.count().desc()).limit(limit)
            ).all()
        return [(r[0], r[1], int(r[2]), int(r[3] or 0)) for r in rows]

    def flow_pairs_for_ioc(self, limit: int = 50000
                           ) -> list[tuple[str | None, str, int | None, str | None, int]]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(S.events.c.src_ip, S.events.c.dst_ip, S.events.c.dst_port,
                       S.events.c.proto, func.count().label("n"))
                .where(self._base(kind=[str(EventKind.FLOW), str(EventKind.FIREWALL)]),
                       S.events.c.dst_ip.is_not(None))
                .group_by(S.events.c.src_ip, S.events.c.dst_ip,
                          S.events.c.dst_port, S.events.c.proto)
                .order_by(func.count().desc()).limit(limit)
            ).all()
        return [(r[0], r[1], r[2], r[3], int(r[4])) for r in rows]

    # ----- pattern helpers for the firewall analyzers ------------------------ #

    def source_profile(self, n: int = 40, **filters: Any) -> list[dict[str, Any]]:
        """Per-source-IP shape: hits, distinct ports, port spread, TTL spread, timing."""
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(
                    S.events.c.src_ip,
                    func.count().label("hits"),
                    func.count(func.distinct(S.events.c.dst_port)).label("ports"),
                    func.min(S.events.c.ts).label("first"),
                    func.max(S.events.c.ts).label("last"),
                    func.min(cast(S.events.c.ttl, Integer)).label("ttl_min"),
                    func.max(cast(S.events.c.ttl, Integer)).label("ttl_max"),
                    func.count(func.distinct(S.events.c.src_port)).label("sports"),
                )
                .where(self._base(**filters), S.events.c.src_ip.is_not(None))
                .group_by(S.events.c.src_ip)
                .order_by(func.count().desc()).limit(n)
            ).mappings().all()
        out = []
        for r in rows:
            first, last = _aware(r["first"]), _aware(r["last"])
            out.append({
                "src_ip": r["src_ip"],
                "hits": int(r["hits"]),
                "distinct_dst_ports": int(r["ports"] or 0),
                "distinct_src_ports": int(r["sports"] or 0),
                "first_seen": first.strftime("%Y-%m-%d %H:%M:%S") if first else None,
                "last_seen": last.strftime("%Y-%m-%d %H:%M:%S") if last else None,
                "duration_hours": round((last - first).total_seconds() / 3600.0, 2)
                if first and last else 0.0,
                "ttl_min": r["ttl_min"],
                "ttl_max": r["ttl_max"],
            })
        return out

    def ports_for_source(self, src_ip: str, n: int = 10) -> list[tuple[int, int]]:
        return [(int(p), c) for p, c in self.top("dst_port", n=n, src_ip=src_ip) if p is not None]

    def return_traffic_count(self, **filters: Any) -> int:
        """TCP sourced from 80/443 - benign conntrack-timeout return traffic."""
        return self.count(proto="tcp", src_port=[80, 443], **filters)

    def subnet_spread(self, n: int = 10, **filters: Any) -> list[tuple[str, int, int]]:
        """(/24 prefix, distinct source IPs, hits) - the mass-scanner sweep shape."""
        rows = self.top("src_ip", n=5000, **filters)
        buckets: dict[str, list[int]] = {}
        for ip, count in rows:
            if not ip or ":" in ip:
                continue
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            prefix = ".".join(parts[:3]) + ".0/24"
            slot = buckets.setdefault(prefix, [0, 0])
            slot[0] += 1
            slot[1] += count
        ranked = sorted(buckets.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))
        return [(p, v[0], v[1]) for p, v in ranked[:n]]
