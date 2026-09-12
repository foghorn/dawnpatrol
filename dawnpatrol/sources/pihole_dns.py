"""Pi-hole v6 DNS query source.

Three behaviours of this API caused silent data loss in production and are
encoded here so they cannot recur:

  * ``cursor`` pagination is a no-op on some builds - it returns the same page
    with the same cursor forever, yielding N duplicated pages that look like a
    successful pull. Offset (``start``) is the working parameter, and the
    integrity gate below catches duplication regardless.
  * The query log contains malformed mDNS names with raw non-UTF-8 bytes.
    Strict decoding aborts the pull partway through. Everything decodes with
    ``errors="replace"``.
  * ``recordsFiltered`` (matching the window) is the loop target, not
    ``recordsTotal`` (the whole database).

Retention is typically ~24h from FTL's in-memory log regardless of the window
requested. That is a known limit, reported as a clamped window rather than as a
collection shortfall.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from ..context import RunContext
from ..models import UTC, CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_bool, read_env, read_int, read_secret
from .base import Source

log = logging.getLogger(__name__)

#: Every status that counts as a block. Filtering only for GRAVITY materially
#: understates the block rate - SPECIAL_DOMAIN and the CNAME variants are real.
BLOCKED_STATUSES = frozenset({
    "GRAVITY", "GRAVITY_CNAME", "DENYLIST", "DENYLIST_CNAME",
    "REGEX", "REGEX_CNAME", "SPECIAL_DOMAIN", "EXTERNAL_BLOCKED_IP",
    "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
})

#: Transient; excluded from block-rate denominators.
TRANSIENT_STATUSES = frozenset({"IN_PROGRESS"})


class PiholeDNSSource(Source):
    name = "pihole_dns"
    kinds = frozenset({EventKind.DNS})
    requires_env = frozenset({"DAWNPATROL_SOURCE_PIHOLE_URL", "DAWNPATROL_SOURCE_PIHOLE_PASSWORD"})
    #: FTL's in-memory query log. Override if your deployment retains more.
    max_window_hours = 24

    PAGE_SIZE = 10000

    # ----- configuration ---------------------------------------------------- #

    @property
    def base_url(self) -> str:
        return (read_env("DAWNPATROL_SOURCE_PIHOLE_URL", "") or "").rstrip("/")

    @property
    def password(self) -> str:
        return read_secret("DAWNPATROL_SOURCE_PIHOLE_PASSWORD").get()

    @property
    def timeout(self) -> int:
        return read_int("DAWNPATROL_SOURCE_PIHOLE_TIMEOUT", 120)

    @property
    def verify_tls(self) -> bool:
        return read_bool("DAWNPATROL_SOURCE_PIHOLE_VERIFY_TLS", False)

    def __init__(self) -> None:
        super().__init__()
        max_hours = read_int("DAWNPATROL_SOURCE_PIHOLE_MAX_WINDOW_HOURS", 0)
        if max_hours > 0:
            self.max_window_hours = max_hours

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout, verify=self.verify_tls)

    # ----- auth -------------------------------------------------------------- #

    def _authenticate(self, client: httpx.Client) -> str:
        resp = client.post(f"{self.base_url}/auth", json={"password": self.password})
        resp.raise_for_status()
        data = _decode(resp)
        sid = (data.get("session") or {}).get("sid")
        if not sid:
            raise RuntimeError("authentication returned no session id")
        return sid

    def _logout(self, client: httpx.Client, sid: str) -> None:
        try:
            client.request("DELETE", f"{self.base_url}/auth", headers={"sid": sid})
        except Exception:  # noqa: BLE001 - best effort
            pass

    # ----- collection --------------------------------------------------------- #

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        effective = self.effective_window(window)
        result = CollectionResult(source=self.name, window=effective, requested_window=window)

        if not self.base_url or not self.password:
            result.errors.append("Pi-hole URL or password not configured")
            return result

        start_ts = int(effective.start.timestamp())
        end_ts = int(effective.end.timestamp())

        with self._client() as client:
            try:
                sid = self._authenticate(client)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"authentication failed: {type(exc).__name__}: {exc}")
                return result
            try:
                headers = {"sid": sid}
                probe = client.get(
                    f"{self.base_url}/queries",
                    params={"from": start_ts, "until": end_ts, "length": 1},
                    headers=headers,
                )
                probe.raise_for_status()
                meta = _decode(probe)
                total = int(meta.get("recordsFiltered") or 0)  # not recordsTotal
                earliest = meta.get("earliest_timestamp")

                if earliest and float(earliest) > start_ts:
                    available = (end_ts - float(earliest)) / 3600.0
                    result.window = Window(
                        start=datetime.fromtimestamp(float(earliest), UTC),
                        end=effective.end,
                    )
                    result.notes.append(
                        f"retention limit: {available:.2f}h of history available "
                        f"against a {effective.hours:.0f}h request. Known limit, "
                        f"not a collection failure."
                    )

                seen: dict[int, dict[str, Any]] = {}
                offset = 0
                while offset < total:
                    resp = client.get(
                        f"{self.base_url}/queries",
                        params={"from": start_ts, "until": end_ts,
                                "length": self.PAGE_SIZE, "start": offset},
                        headers=headers,
                    )
                    resp.raise_for_status()
                    payload = _decode(resp)
                    batch = payload.get("queries") or []
                    result.pages += 1
                    if not batch:
                        break
                    before = len(seen)
                    for q in batch:
                        qid = q.get("id")
                        if qid is not None:
                            seen[int(qid)] = q
                    if len(seen) == before:
                        # A full page yielding zero new ids is the cursor-repeat
                        # signature. Stop rather than spin.
                        result.complete = False
                        result.errors.append(
                            f"pagination stalled at offset {offset}: a full page "
                            f"produced no new record ids"
                        )
                        break
                    offset += len(batch)
                    if result.pages > 200:
                        result.complete = False
                        result.errors.append("pagination exceeded 200 pages; aborted")
                        break

                result.reported_total = total
                result.events = [self._normalize(q) for q in seen.values()]
                result.events = [e for e in result.events if e is not None]
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"{type(exc).__name__}: {exc}")
                result.complete = False
            finally:
                self._logout(client, sid)

        return result

    # ----- normalization -------------------------------------------------------- #

    def _normalize(self, q: dict[str, Any]) -> Event | None:
        raw_ts = q.get("time")
        if raw_ts is None:
            return None
        try:
            ts = datetime.fromtimestamp(float(raw_ts), UTC)
        except (TypeError, ValueError, OSError):
            return None

        status = str(q.get("status") or "").upper()
        if status in TRANSIENT_STATUSES:
            return None

        domain = _clean_domain(q.get("domain"))
        client_ip = None
        client_field = q.get("client")
        if isinstance(client_field, dict):
            client_ip = client_field.get("ip") or client_field.get("name")
        elif client_field:
            client_ip = str(client_field)

        upstream = q.get("upstream")
        if isinstance(upstream, dict):
            upstream = upstream.get("name") or upstream.get("ip")

        return Event(
            ts=ts,
            source=self.name,
            kind=EventKind.DNS,
            dedup_key=Event.make_dedup_key(self.name, q.get("id")),
            domain=domain,
            qtype=(q.get("type") or None),
            blocked=status in BLOCKED_STATUSES,
            block_reason=status if status in BLOCKED_STATUSES else None,
            upstream=str(upstream) if upstream else None,
            **self.assign_zones(client_ip=str(client_ip) if client_ip else None),
        )

    # ----- probes ---------------------------------------------------------------- #

    def self_test(self, ctx: RunContext) -> list[Probe]:
        probes: list[Probe] = []
        if not self.base_url or not self.password:
            return [Probe(name="config", request="(none)", ok=False,
                          detail="URL or password missing")]
        with self._client() as client:
            try:
                sid = self._authenticate(client)
            except Exception as exc:  # noqa: BLE001
                return [Probe(name="auth", request="POST /auth", ok=False,
                              detail=f"{type(exc).__name__}: {exc}")]
            headers = {"sid": sid}
            try:
                for name, params in (
                    ("summary-no-filter", None),
                    ("queries-last-hour", {"from": int(ctx.window.last_hour().start.timestamp()),
                                           "until": int(ctx.window.end.timestamp()), "length": 1}),
                ):
                    path = "/stats/summary" if params is None else "/queries"
                    try:
                        resp = client.get(f"{self.base_url}{path}", params=params, headers=headers)
                        payload = _decode(resp)
                        records = payload.get("recordsFiltered")
                        if records is None:
                            queries = payload.get("queries")
                            records = queries.get("total") if isinstance(queries, dict) else None
                        probes.append(Probe(name=name, request=path,
                                            ok=resp.status_code == 200,
                                            status=resp.status_code, records=records))
                    except Exception as exc:  # noqa: BLE001
                        probes.append(Probe(name=name, request=path, ok=False,
                                            detail=f"{type(exc).__name__}: {exc}"))
            finally:
                self._logout(client, sid)
        return probes

    def extra_health_notes(self, result: CollectionResult) -> list[str]:
        notes: list[str] = []
        if result.events:
            blocked = sum(1 for e in result.events if e.blocked)
            rate = 100.0 * blocked / len(result.events)
            notes.append(f"block rate {rate:.1f}% ({blocked} of {len(result.events)})")
        if result.clamped:
            notes.append(
                f"window clamped to {result.window.hours:.2f}h by DNS log retention; "
                f"never extrapolate this to the full requested window"
            )
        return notes


def _clean_domain(raw: Any) -> str | None:
    """Normalize a domain and strip the control characters that survive tolerant
    decoding, so they never reach the database, the model, or a report."""
    text = (raw or "")
    if not isinstance(text, str):
        text = str(text)
    cleaned = "".join(ch for ch in text if ch.isprintable() and ch != "\ufffd")
    return cleaned.strip().rstrip(".").lower() or None


def _decode(resp: httpx.Response) -> dict[str, Any]:
    """Decode tolerantly. Malformed mDNS names carry raw non-UTF-8 bytes."""
    import json

    text = resp.content.decode("utf-8", errors="replace")
    try:
        # strict=False permits raw control characters inside string literals.
        # Tolerant decoding alone is not enough: a malformed mDNS name such as
        # b"lb._dns-sd._udp.\xc0\x01\x02" still leaves \x01\x02 in the string,
        # which strict JSON rejects - aborting the whole paginated pull.
        data = json.loads(text, strict=False)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-JSON response ({resp.status_code}): {text[:200]}") from exc
    return data if isinstance(data, dict) else {"data": data}
