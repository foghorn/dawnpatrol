"""Output plugin contract.

An output pairs a renderer with a destination. Renderers are shared library
code, so a new destination inherits a correct report body instead of
re-implementing the formatting contract.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from ..context import RunContext
from ..models import DeliveryResult, Report, Status
from ..secrets import read_bool, read_env, read_list

log = logging.getLogger(__name__)

ALL_STATUSES = frozenset({Status.GREEN, Status.AMBER, Status.RED})


class Output(ABC):
    name: str = ""
    #: Renderer key: "plaintext" | "markdown" | "json".
    renderer: str = "plaintext"
    requires_env: frozenset[str] = frozenset()
    #: Default delivery policy. Overridden per output via
    #: ``DAWNPATROL_OUTPUT_<NAME>_RUN_WHEN`` (e.g. "AMBER,RED" or "important").
    default_run_when: frozenset[Status] = ALL_STATUSES
    #: When true, deliver only when the report is actually interesting.
    default_important_only: bool = False

    def __init__(self) -> None:
        self.run_when: frozenset[Status] = self.default_run_when
        self.important_only: bool = self.default_important_only

    # ----- delivery policy -------------------------------------------------- #

    def configure(self, env_prefix: str = "DAWNPATROL_OUTPUT_") -> None:
        key = f"{env_prefix}{self.name.upper()}_RUN_WHEN"
        raw = read_env(key, "")
        if raw:
            tokens = [t.strip().upper() for t in raw.split(",") if t.strip()]
            if "IMPORTANT" in tokens:
                self.important_only = True
                self.run_when = ALL_STATUSES
            elif "NEVER" in tokens:
                self.run_when = frozenset()
            elif "ALWAYS" in tokens:
                self.important_only = False
                self.run_when = ALL_STATUSES
            else:
                self.run_when = frozenset(
                    Status(t) for t in tokens if t in Status.__members__
                )
        self.important_only = read_bool(
            f"{env_prefix}{self.name.upper()}_IMPORTANT_ONLY", self.important_only
        )

    def should_run(self, report: Report) -> tuple[bool, str]:
        """Decide delivery. Returns (run, reason-if-skipped)."""
        if not self.run_when:
            return False, "disabled by RUN_WHEN=never"
        if report.status not in self.run_when:
            return False, f"status {report.status} not in {sorted(s.value for s in self.run_when)}"
        if self.important_only and not report.has_important():
            return False, "important_only: nothing notable this period"
        return True, ""

    # ----- delivery --------------------------------------------------------- #

    @abstractmethod
    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        """Deliver the rendered report. Must not raise; return ok=False instead."""

    @staticmethod
    def env_list(name: str) -> list[str]:
        return read_list(name)

    def __repr__(self) -> str:
        return f"<Output {self.name}>"
