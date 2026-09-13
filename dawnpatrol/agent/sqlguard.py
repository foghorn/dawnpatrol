"""Validation for the agent's read-only SQL tool.

The capability is worth a lot - it lets the model chase a hypothesis it forms
mid-run instead of being limited to queries we anticipated. The safety comes
from structure, not from asking nicely: one statement, SELECT only, an allowed
table list, an injected LIMIT, and a row cap on the way out.
"""

from __future__ import annotations

import re

from ..errors import DawnPatrolError
from ..schema import AGENT_READABLE

MAX_SQL_LENGTH = 4000
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|replace|grant|revoke|"
    r"attach|detach|pragma|vacuum|reindex|savepoint|begin|commit|rollback|"
    r"load_file|outfile|dumpfile|into\s+outfile|sleep|benchmark)\b",
    re.IGNORECASE,
)
_COMMENT = re.compile(r"(--[^\n]*|/\*.*?\*/)", re.DOTALL)
# `(?:\s|\()*` absorbs any mix of whitespace and open-parens between the
# keyword and the identifier, so `FROM(events)`, `FROM (events)`, and
# `FROM((events))` are all caught the same as `FROM events` - a bare
# whitespace requirement here let a query hide its table reference from the
# allowlist/run-scope checks below by simply omitting the space.
_TABLE_REF = re.compile(
    r"\b(?:from|join)(?:\s|\()*([`\"\[]?)([a-zA-Z_][a-zA-Z0-9_]*)\1",
    re.IGNORECASE,
)
# A subquery like `FROM (SELECT ...)` makes the pattern above capture
# "select"/"with" as if it were a table name; those aren't real references
# and the nested FROM inside the subquery is matched separately anyway.
_NOT_A_TABLE = {"select", "with"}
_LIMIT_RE = re.compile(r"\blimit\s+(\d+)", re.IGNORECASE)


class SQLRejected(DawnPatrolError):
    """The statement failed validation and was not executed."""


def validate(sql: str, run_id: str, max_rows: int = DEFAULT_LIMIT) -> tuple[str, int]:
    """Return (safe_sql, row_cap) or raise :class:`SQLRejected`."""
    if not sql or not sql.strip():
        raise SQLRejected("empty query")
    if len(sql) > MAX_SQL_LENGTH:
        raise SQLRejected(f"query exceeds {MAX_SQL_LENGTH} characters")

    stripped = _COMMENT.sub(" ", sql).strip().rstrip(";").strip()
    if ";" in stripped:
        raise SQLRejected("only a single statement is allowed; remove the ';'")

    lowered = stripped.lower()
    if not (lowered.startswith("select") or lowered.startswith("with")):
        raise SQLRejected("only SELECT (or WITH ... SELECT) statements are allowed")
    if _FORBIDDEN.search(stripped):
        raise SQLRejected("query contains a forbidden keyword; this tool is read-only")

    referenced = {
        m.group(2).lower() for m in _TABLE_REF.finditer(stripped)
    } - _NOT_A_TABLE
    # CTE names are self-referential and legitimate; allow anything defined by WITH.
    cte_names = {
        m.group(1).lower()
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(", stripped, re.IGNORECASE)
    }
    illegal = referenced - AGENT_READABLE - cte_names
    if illegal:
        raise SQLRejected(
            f"table(s) not readable by this tool: {', '.join(sorted(illegal))}. "
            f"Readable tables: {', '.join(sorted(AGENT_READABLE))}"
        )

    # Scope to this run unless the model deliberately queried a long-term table.
    long_term = referenced & {"ioc_dns", "ioc_flow", "entities", "metrics"}
    if "events" in referenced and "run_id" not in lowered and not long_term:
        raise SQLRejected(
            f"queries against `events` must filter by run_id. "
            f"Add: WHERE run_id = '{run_id}'"
        )

    cap = max_rows
    found = _LIMIT_RE.search(stripped)
    if found:
        cap = min(int(found.group(1)), MAX_LIMIT)
    else:
        cap = min(max_rows, MAX_LIMIT)
        stripped = f"{stripped} LIMIT {cap}"
    return stripped, cap


def describe_schema(run_id: str, dialect: str) -> str:
    """Schema documentation handed to the model alongside the tool."""
    return f"""Read-only SQL is available over these tables ({dialect} dialect).

events - one row per normalized observation. Scope to run_id = '{run_id}'.
  ts, source, kind, dedup_key
  kind is one of: firewall, dns, system, auth, ids, flow, http, other
  network : src_ip, dst_ip, src_port, dst_port, proto, action,
            iface_in, iface_out, ttl, pkt_len
  dns     : domain, qtype, blocked (bool), block_reason, upstream, client_ip
  system  : device, program, severity, message, user
  derived : src_zone, dst_zone  (resolved from the site profile)

metrics    - key, value_num, value_text, unit, section, ts, run_id
signals    - signal_id, analyzer, title, taxonomy, severity_hint, confidence,
             entities_json, evidence_json, run_id
entities   - etype, value, first_seen, last_seen, occurrences
             (the long-term baseline; this is how you tell novel from routine)
ioc_dns    - day, client_ip, domain, queries, blocked   (long-term, ~180 days)
ioc_flow   - day, src_ip, dst_ip, dst_port, proto, hits (long-term, ~180 days)

Rules enforced by the tool, not by convention:
  * one SELECT statement, no semicolons, no writes of any kind
  * queries against `events` must include run_id = '{run_id}'
  * a LIMIT is added when you omit one; results are capped at {MAX_LIMIT} rows

Useful shapes:
  SELECT dst_port, COUNT(*) c, COUNT(DISTINCT src_ip) srcs
    FROM events WHERE run_id='{run_id}' AND kind='firewall' AND action='drop'
    GROUP BY dst_port ORDER BY c DESC LIMIT 20;

  SELECT client_ip, domain, COUNT(*) c
    FROM events WHERE run_id='{run_id}' AND kind='dns' AND blocked=1
    GROUP BY client_ip, domain ORDER BY c DESC LIMIT 25;

  SELECT value, first_seen, occurrences FROM entities
    WHERE etype='domain' AND value LIKE '%example%' ORDER BY first_seen DESC;
"""
