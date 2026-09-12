"""In-process cron scheduler.

One process, PID 1 is the app, logs go to stdout unmodified, and the schedule is
a plain environment variable. An empty schedule means "run once and exit", which
is what you want for testing or for driving DawnPatrol from an external scheduler.
"""

from __future__ import annotations

import logging
import signal
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import CroniterBadCronError, croniter

from .config import Settings
from .errors import ConfigError
from .models import UTC

log = logging.getLogger(__name__)

HEARTBEAT_NAME = "heartbeat"


class Scheduler:
    def __init__(self, settings: Settings, job: Callable[[], None]) -> None:
        self.settings = settings
        self.job = job
        self._stop = threading.Event()
        self.heartbeat_path = settings.data_dir / HEARTBEAT_NAME

        try:
            self.tz = ZoneInfo(settings.schedule.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ConfigError(
                f"unknown timezone {settings.schedule.timezone!r}: {exc}"
            ) from exc

        cron = settings.schedule.cron
        if cron and not croniter.is_valid(cron):
            raise ConfigError(f"invalid cron expression: {cron!r}")
        self.cron = cron

    # ----- signals ---------------------------------------------------------- #

    def install_signal_handlers(self) -> None:
        def handler(signum: int, _frame: object) -> None:
            log.info("received signal %s; finishing current work then exiting", signum)
            self._stop.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass  # not on the main thread; the caller handles shutdown

    def touch_heartbeat(self) -> None:
        try:
            self.heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
            self.heartbeat_path.write_text(
                datetime.now(UTC).isoformat(), encoding="utf-8"
            )
        except OSError as exc:
            log.warning("could not write heartbeat: %s", exc)

    # ----- loop ------------------------------------------------------------- #

    def next_fire(self, after: datetime | None = None) -> datetime:
        base = (after or datetime.now(self.tz)).astimezone(self.tz)
        return croniter(self.cron, base).get_next(datetime).astimezone(UTC)

    def serve(self) -> int:
        self.install_signal_handlers()
        self.touch_heartbeat()

        if self.settings.schedule.run_on_start or not self.cron:
            self._run_once("startup")
        if not self.cron:
            log.info("no schedule configured; exiting after a single run")
            return 0

        log.info("scheduler active: %r in %s", self.cron, self.tz.key)
        while not self._stop.is_set():
            target = self.next_fire()
            delay = (target - datetime.now(UTC)).total_seconds()
            if self.settings.schedule.jitter_seconds:
                delay += self.settings.schedule.jitter_seconds
            log.info("next run at %s UTC (in %s)",
                     target.strftime("%Y-%m-%d %H:%M:%S"),
                     timedelta(seconds=int(max(0, delay))))

            # Wake periodically so the heartbeat stays fresh and a stop signal is
            # honoured promptly even with a long gap between runs.
            while delay > 0 and not self._stop.is_set():
                slice_seconds = min(delay, 60.0)
                if self._stop.wait(slice_seconds):
                    break
                delay -= slice_seconds
                self.touch_heartbeat()

            if self._stop.is_set():
                break
            self._run_once("scheduled")

        log.info("scheduler stopped")
        return 0

    def _run_once(self, trigger: str) -> None:
        log.info("--- %s run beginning ---", trigger)
        try:
            self.job()
        except Exception:  # noqa: BLE001 - a failed run must never kill the daemon
            log.exception("run failed; the scheduler continues")
        finally:
            self.touch_heartbeat()


def heartbeat_age_seconds(data_dir: Path) -> float | None:
    path = data_dir / HEARTBEAT_NAME
    if not path.is_file():
        return None
    try:
        stamp = datetime.fromisoformat(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - stamp).total_seconds()
