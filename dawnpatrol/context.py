"""Per-run context threaded through every stage and plugin."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .models import UTC, Window

if TYPE_CHECKING:
    from .config import Settings
    from .profile import Profile
    from .store import Store


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


@dataclass(slots=True)
class RunContext:
    run_id: str
    started_at: datetime
    window: Window
    settings: "Settings"
    profile: "Profile"
    store: "Store"
    run_number: int = 1
    dry_run: bool = False
    notes: list[str] = field(default_factory=list)
    stage_timings: dict[str, float] = field(default_factory=dict)
    canary_entities: set[str] = field(default_factory=set)

    def note(self, text: str) -> None:
        if text and text not in self.notes:
            self.notes.append(text)

    def describe(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "window": str(self.window),
            "run_number": self.run_number,
            "dry_run": self.dry_run,
        }
