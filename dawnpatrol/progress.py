"""Live progress of the run in flight, for the web console and MCP.

While a run is active, a logging handler on the ``dawnpatrol`` logger copies
its log lines into ``<data_dir>/run-progress.json``. Everything a progress view
needs is already logged by the pipeline:

* ``stage <name>: started`` / ``done in`` / ``failed after`` (``runner._timed``);
* ``model call <n>: sent to ...`` (the providers);
* ``tool <n>/<max>: ...`` (the investigation tools).

So nothing in the pipeline reports progress explicitly. A file, not memory,
because a run started with ``docker exec ... dawnpatrol run`` is a different
process from the server that shows it. Writes are throttled to about one a
second, except stage changes and the finish, which are written at once.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FILE_NAME = "run-progress.json"
#: Stage order as the runner executes them (``runner.py``).
STAGES = ("collect", "verify", "persist", "analyze", "investigate", "adjudicate",
          "render", "deliver")
LOG_LINES = 150
_STAGE = re.compile(r"^stage (\w+): (started|done in|failed after)\s*(.*)$")
_MODEL = re.compile(r"^model call (\d+): sent")
_TOOL = re.compile(r"^tool (\d+)/(\d+):")
_MIN_INTERVAL = 1.0


def progress_path(data_dir: str | Path) -> Path:
    return Path(data_dir) / FILE_NAME


class RunProgress(logging.Handler):
    """Tracks one run. Use as a context manager around ``Runner.run``."""

    def __init__(self, data_dir: str | Path, *, run_id: str, trigger: str,
                 window_hours: float | None = None, sources: list[str] | None = None,
                 send_email: bool = True, redact: Any = None) -> None:
        super().__init__(level=logging.INFO)
        self.path = progress_path(data_dir)
        self._redact = redact or (lambda s: s)
        self._lock = threading.Lock()
        self._last_write = 0.0
        self._timer: threading.Timer | None = None
        self._log: deque[dict[str, str]] = deque(maxlen=LOG_LINES)
        now = _now()
        self.state: dict[str, Any] = {
            "state": "running", "run_id": run_id, "trigger": trigger, "pid": os.getpid(),
            "started_at": now, "updated_at": now, "finished_at": None,
            "window_hours": window_hours, "sources": sources, "send_email": send_email,
            "current_stage": None,
            "stages": {s: {"state": "pending", "seconds": None} for s in STAGES},
            "model_calls": 0, "tool_calls": 0, "tool_budget": None,
            "result": None, "log": [],
        }

    # ----- lifecycle ---------------------------------------------------------- #

    def __enter__(self) -> RunProgress:
        logging.getLogger("dawnpatrol").addHandler(self)
        self._write(force=True)
        return self

    def __exit__(self, *exc: Any) -> None:
        logging.getLogger("dawnpatrol").removeHandler(self)
        if self.state["state"] == "running":       # finish() wasn't called
            self.finish(error="run ended unexpectedly")

    def finish(self, *, status: str | None = None, findings: int | None = None,
               error: str | None = None, stopped_after: str = "") -> None:
        with self._lock:
            self.state["state"] = "failed" if error else "finished"
            self.state["finished_at"] = _now()
            self.state["current_stage"] = None
            self.state["result"] = {"status": status, "finding_count": findings,
                                    "error": self._redact(error) if error else None,
                                    "stopped_after": stopped_after or None}
        self._write(force=True)

    # ----- logging.Handler ---------------------------------------------------- #

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return
        force = False
        with self._lock:
            st = self.state
            m = _STAGE.match(msg)
            if m and m.group(1) in st["stages"]:
                name, what, took = m.groups()
                stage = st["stages"][name]
                if what == "started":
                    stage["state"], st["current_stage"] = "active", name
                    stage["started_at"] = _now()
                else:
                    stage["state"] = "done" if what == "done in" else "failed"
                    stage["took"] = took
                    stage["seconds"] = _seconds(took)
                    if st["current_stage"] == name:
                        st["current_stage"] = None
                force = True
            elif m2 := _MODEL.match(msg):
                st["model_calls"] = max(st["model_calls"], int(m2.group(1)))
            elif m3 := _TOOL.match(msg):
                st["tool_calls"] = max(st["tool_calls"], int(m3.group(1)))
                st["tool_budget"] = int(m3.group(2))
            self._log.append({
                "ts": datetime.fromtimestamp(record.created, UTC).strftime("%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name.removeprefix("dawnpatrol."),
                "msg": self._redact(msg)[:500],
            })
        self._write(force=force)

    # ----- file --------------------------------------------------------------- #

    def _flush(self) -> None:
        with self._lock:
            self._timer = None
        self._write(force=True)

    def _write(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_write < _MIN_INTERVAL:
            # Throttled: make sure this update still lands, even if the next log
            # line is minutes away (a model call in progress).
            with self._lock:
                if self._timer is None:
                    delay = _MIN_INTERVAL - (now - self._last_write)
                    self._timer = threading.Timer(max(delay, 0.05), self._flush)
                    self._timer.daemon = True
                    self._timer.start()
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._last_write = now
            self.state["updated_at"] = _now()
            self.state["log"] = list(self._log)
            body = json.dumps(self.state, default=str)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(body, encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass                       # progress is a convenience; never break a run


def read_progress(data_dir: str | Path) -> dict[str, Any]:
    """The last run's progress, or ``{"state": "idle"}``. A file still saying
    "running" whose process is gone is reported as ``interrupted``."""
    try:
        data = json.loads(progress_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "idle"}
    if not isinstance(data, dict):
        return {"state": "idle"}
    if data.get("state") == "running" and not _alive(data.get("pid")):
        data["state"] = "interrupted"
    try:
        started = datetime.fromisoformat(data["started_at"])
        end = (datetime.fromisoformat(data["finished_at"]) if data.get("finished_at")
               else datetime.now(UTC))
        data["elapsed_seconds"] = round((end - started).total_seconds())
    except (KeyError, TypeError, ValueError):
        pass
    return data


def _alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
    except (TypeError, ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True
    return True


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _seconds(text: str) -> float | None:
    """``0.4s`` / ``52s`` / ``3m 07s`` (runner._elapsed) back to seconds."""
    m = re.match(r"^(?:(\d+)m\s*)?([\d.]+)s$", text.strip())
    if not m:
        return None
    return int(m.group(1) or 0) * 60 + float(m.group(2))
