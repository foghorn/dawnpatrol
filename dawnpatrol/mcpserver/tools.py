"""Tool implementations for the external-agent MCP surface.

Every read here reuses the same primitives the in-run investigation agent
uses (``agent.sqlguard`` for SQL safety, ``Store`` for persisted history,
``Profile.as_context`` for network documentation) rather than opening a
second, less-audited path to the same data. The one non-read tool,
``trigger_analysis``, does nothing a human running ``dawnpatrol run`` could
not already do - it is the same :class:`~dawnpatrol.runner.Runner` call.
"""

from __future__ import annotations

import asyncio
import glob
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..agent import sqlguard
from ..config import Settings
from ..profile import Profile
from ..store import Store

log = logging.getLogger(__name__)

# A run triggered over MCP never emails - the whole point is a quiet,
# on-demand look. File output still happens, same as any other run, so the
# result is discoverable afterwards through get_report / get_latest_report.
MCP_SKIP_OUTPUTS = frozenset({"smtp"})


class ToolContext:
    """Everything a tool function needs, bound once when the server starts."""

    def __init__(self, *, settings: Settings, profile: Profile, store: Store,
                 trigger_run: Callable[..., Any]) -> None:
        self.settings = settings
        self.profile = profile
        self.store = store
        self.trigger_run = trigger_run

    # ----- reports ----------------------------------------------------------- #

    def list_reports(self, limit: int = 10) -> dict[str, Any]:
        limit = max(1, min(limit, 100))
        rows = self.store.recent_runs(limit)
        return {"runs": [_jsonable_run(r) for r in rows]}

    def get_latest_report(self, format: str = "text") -> dict[str, Any]:
        suffix = _suffix_for(format)
        path = self.settings.output_dir / f"latest.{suffix}"
        return _read_report_file(path)

    def get_report(self, run_id: str, format: str = "text") -> dict[str, Any]:
        run_id = run_id.strip()
        if not run_id:
            return {"error": "run_id is required"}
        suffix = _suffix_for(format)
        matches = glob.glob(str(self.settings.output_dir / "*" / f"report-{run_id}.{suffix}"))
        if not matches:
            return {"error": f"no {suffix} report found on disk for run_id {run_id!r}. "
                              f"Use list_reports to see available run ids."}
        return _read_report_file(Path(matches[0]))

    # ----- raw and aggregate data --------------------------------------------- #

    def describe_event_schema(self) -> str:
        latest = self.store.recent_runs(1)
        run_id = latest[0]["run_id"] if latest else "<run_id>"
        return sqlguard.describe_schema(run_id, self.settings.db.dialect)

    def query_events(self, sql: str, limit: int = 200) -> dict[str, Any]:
        latest = self.store.recent_runs(1)
        run_id = latest[0]["run_id"] if latest else ""
        try:
            safe_sql, cap = sqlguard.validate(sql, run_id, limit)
        except sqlguard.SQLRejected as exc:
            return {"error": f"query rejected: {exc}"}
        try:
            columns, rows = self.store.readonly_sql(safe_sql, max_rows=cap)
        except Exception as exc:  # noqa: BLE001 - surface the error to the caller
            return {"error": f"query failed: {type(exc).__name__}: {exc}"}
        return {"columns": columns, "row_count": len(rows), "rows": rows}

    def get_metric_history(self, key: str, days: int = 30) -> dict[str, Any]:
        days = max(1, min(days, 365))
        series = self.store.metric_history(key, days=days)
        if not series:
            return {"key": key, "days": days, "series": [],
                     "note": "no history for this metric in the requested window"}
        return {"key": key, "days": days, "series": series}

    # ----- network documentation ---------------------------------------------- #

    def get_network_profile(self) -> str:
        return self.profile.as_context()

    # ----- agent notebook -------------------------------------------------------- #
    # Only registered when DAWNPATROL_MCP_NOTEBOOK_ENABLED=true - see server.py.

    def read_notebook(self, limit: int = 500) -> dict[str, Any]:
        limit = max(1, min(limit, 2000))
        entries = self.store.list_notebook_entries(limit=limit)
        return {"entries": entries, "count": len(entries),
                "injected_into_future_runs": min(len(entries),
                                                 self.settings.mcp.notebook_max_injected)}

    def add_notebook_entry(self, text: str, author: str = "") -> dict[str, Any]:
        text = (text or "").strip()
        if not text:
            return {"error": "text is required"}
        max_chars = self.settings.mcp.notebook_max_entry_chars
        if len(text) > max_chars:
            return {"error": f"entry is {len(text)} characters, over the "
                             f"{max_chars}-character limit "
                             f"(DAWNPATROL_MCP_NOTEBOOK_MAX_ENTRY_CHARS). "
                             f"Split it into more than one entry."}
        entry_id = self.store.add_notebook_entry(text, author=(author or "").strip()[:255])
        return {"id": entry_id, "stored": True,
                "note": "Included in the context of every future run until the "
                        f"entry count exceeds the most recent "
                        f"{self.settings.mcp.notebook_max_injected} - see read_notebook."}

    def delete_notebook_entry(self, entry_id: int) -> dict[str, Any]:
        deleted = self.store.delete_notebook_entry(entry_id)
        if not deleted:
            return {"error": f"no notebook entry with id {entry_id}. "
                             f"Use read_notebook to see current ids."}
        return {"id": entry_id, "deleted": True}

    # ----- discovery ----------------------------------------------------------- #

    def list_source_plugins(self) -> dict[str, Any]:
        from .. import sources as sources_pkg
        from ..registry import discover, env_satisfied
        from ..sources.base import Source

        result = []
        for cls in discover(sources_pkg, Source):
            satisfied, missing = env_satisfied(cls.requires_env)
            allowed = self.settings.allowed("source", cls.name)
            state = ("disabled (config)" if not allowed
                     else "enabled" if satisfied
                     else f"disabled (needs {', '.join(missing)})")
            result.append({"name": cls.name, "state": state})
        return {"sources": result}

    # ----- cross-source device directory ------------------------------------------ #
    # Generic, core functionality - not tied to any one source plugin. The data
    # already exists: every run's Report carries `devices` (dawnpatrol/devices.py,
    # merged across whichever collectors contributed one), and file_report.py
    # already writes it to latest.json like the rest of the report. No separate
    # persistence of our own - just read the same file get_latest_report reads.

    def get_device_directory(self, ip: str = "") -> dict[str, Any]:
        path = self.settings.output_dir / "latest.json"
        if not path.is_file():
            return {"error": "no report has been generated yet"}
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {"error": f"latest.json is not valid JSON: {exc}"}
        devices = report.get("devices") or []
        if not devices:
            return {"error": "the most recent report recorded no device information - "
                             "populated by whichever source plugins are enabled and "
                             "report device-level data (see list_source_plugins)"}
        ip = ip.strip()
        if ip:
            match = next((d for d in devices if d.get("ip") == ip), None)
            if match is None:
                known = ", ".join(d.get("ip", "") for d in devices[:50])
                return {"error": f"no directory entry for {ip!r}. Known IPs: {known}"}
            return match
        return {"devices": devices, "run_id": report.get("run_id")}

    # ----- trigger --------------------------------------------------------------- #

    async def trigger_analysis(self, sources: list[str] | None = None,
                                window_hours: int | None = None) -> dict[str, Any]:
        outcome, busy = await asyncio.to_thread(
            self.trigger_run, sources=sources, window_hours=window_hours,
            skip_outputs=MCP_SKIP_OUTPUTS,
        )
        if busy:
            return {"error": busy}
        if outcome is None:
            return {"error": "run did not produce an outcome"}
        if outcome.error:
            return {"error": outcome.error, "run_id": None}
        report = outcome.report
        result: dict[str, Any] = {
            "run_id": report.run_id if report else None,
            "status": report.status.value if report else None,
            "finding_count": report.finding_count if report else 0,
            "cost_usd": round(report.usage.cost_usd, 4) if report else 0.0,
            "email_sent": False,
        }
        if report:
            result["executive_summary"] = report.executive_summary
        return result


def _suffix_for(format: str) -> str:
    fmt = (format or "text").strip().lower()
    return {"text": "txt", "plaintext": "txt", "txt": "txt",
            "json": "json", "markdown": "md", "md": "md"}.get(fmt, "txt")


def _read_report_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"error": f"no report file at {path}"}
    body = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        try:
            return {"run_id": path.stem, "report": json.loads(body)}
        except json.JSONDecodeError:
            pass
    return {"path": str(path), "body": body}


def _jsonable_run(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key == "stages_json":
            continue
        out[key] = value.isoformat() if hasattr(value, "isoformat") else value
    return out
