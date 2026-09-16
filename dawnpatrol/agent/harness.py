"""Drives the model stage: bundle in, validated analysis out."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analyzers.baseline import Baseline
from ..budget import Budget
from ..config import Settings
from ..context import RunContext
from ..enrichment.broker import EnrichmentBroker
from ..errors import BudgetExceeded, ProviderError
from ..models import Metric, Signal, SourceHealth, TokenUsage
from ..profile import Profile
from ..providers.base import AgentRun, Provider
from ..query import EventQuery
from ..store import Store
from .bundle import build_bundle, build_task_message
from .tools import ToolBox

log = logging.getLogger(__name__)

PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass(slots=True)
class HarnessResult:
    analysis: dict[str, Any] | None = None
    usage: TokenUsage = field(default_factory=TokenUsage)
    error: str | None = None
    tool_calls: int = 0
    turns: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.analysis is not None


def load_prompt(name: str) -> str:
    path = PROMPT_DIR / f"{name}.md"
    if not path.is_file():
        raise ProviderError(f"prompt {name} not found at {path}")
    return path.read_text(encoding="utf-8")


class Harness:
    def __init__(
        self,
        *,
        provider: Provider,
        settings: Settings,
        store: Store,
        profile: Profile,
        broker: EnrichmentBroker,
    ) -> None:
        self.provider = provider
        self.settings = settings
        self.store = store
        self.profile = profile
        self.broker = broker

    def run(
        self,
        *,
        ctx: RunContext,
        health: list[SourceHealth],
        metrics: list[Metric],
        signals: list[Signal],
        notes: list[str],
        baseline: Baseline,
    ) -> HarnessResult:
        result = HarnessResult()

        ok, reason = self.provider.available()
        if not ok:
            result.error = f"provider {self.provider.name} unavailable: {reason}"
            return result

        query = EventQuery(self.store, ctx.run_id)
        toolbox = ToolBox(
            store=self.store,
            query=query,
            profile=self.profile,
            baseline=baseline,
            broker=self.broker,
            signals=signals,
            run_id=ctx.run_id,
            max_calls=self.settings.ai.max_tool_calls,
            devices=ctx.devices,
        )

        bundle = build_bundle(
            window=ctx.window,
            profile=self.profile,
            health=health,
            metrics=metrics,
            signals=signals,
            notes=notes,
            watchlist=baseline.watchlist(),
            enrichment_budgets=self.broker.budget_report(),
            baseline_available=baseline.has_baseline(),
            run_id=ctx.run_id,
            devices=ctx.devices,
        )

        degraded_note = ""
        unusable = [h.source for h in health if not h.usable]
        if unusable:
            degraded_note = (
                f"These sources did not produce usable data this run: "
                f"{', '.join(unusable)}. Read their health state carefully - SUSPECT "
                f"means the cause was not established, which is different from a "
                f"confirmed outage."
            )

        system_static = load_prompt("system")
        system_context = self.profile.as_context()
        if self.settings.mcp.notebook_enabled:
            notebook_block = self._notebook_context()
            if notebook_block:
                system_context = f"{system_context}\n\n{notebook_block}"
        user_message = "\n\n".join([
            build_task_message(bundle, ctx.window, degraded_note),
            load_prompt("task"),
        ])

        budget = Budget(
            max_cost_usd=self.settings.ai.max_cost_usd,
            max_turns=self.settings.ai.max_turns,
            max_tool_calls=self.settings.ai.max_tool_calls,
        )

        def on_turn(usage: TokenUsage) -> None:
            budget.check(usage)

        log.info("running %s (%s), budget: %s", self.provider.name,
                 self.settings.ai.model, budget.describe())

        try:
            run: AgentRun = self.provider.run_agent(
                system_static=system_static,
                system_context=system_context,
                user_message=user_message,
                tools=toolbox.specs(),
                max_turns=self.settings.ai.max_turns,
                on_turn=on_turn,
            )
        except BudgetExceeded as exc:
            result.error = str(exc)
            result.notes.append(
                "the analysis stage was stopped by its cost ceiling; the report "
                "below is statistics-only"
            )
            return result
        except Exception as exc:  # noqa: BLE001
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        result.usage = run.usage
        result.tool_calls = len(run.tool_calls)
        result.turns = run.turns

        if run.transcript_note:
            result.notes.append(run.transcript_note)

        failed_tools = [t for t in run.tool_calls if not t.ok]
        if failed_tools:
            result.notes.append(
                f"{len(failed_tools)} tool call(s) failed during analysis: "
                + "; ".join(f"{t.name}: {t.detail}" for t in failed_tools[:3])
            )

        if not run.ok:
            result.error = run.error or "provider returned no analysis"
            return result

        # A cache that never reads is a silent multiplier on cost.
        if run.usage.calls > 1 and run.usage.cache_read_tokens == 0:
            result.notes.append(
                "prompt cache never hit across multiple model calls; check that "
                "nothing volatile precedes the cache breakpoint"
            )

        result.analysis = run.analysis
        return result

    def _notebook_context(self) -> str:
        """Agent-submitted notes, bounded to the most recent N (§ MCP notebook).

        Appended after the profile block, inside the same cached system-prompt
        segment - so, like the profile, this must be read as "whatever it is
        right now," not depended on to be identical run over run. A note being
        added or aging out of the injected window invalidates the prompt cache
        for that one run, the same way an edited profile.yml would.
        """
        entries = self.store.recent_notebook_entries(self.settings.mcp.notebook_max_injected)
        if not entries:
            return ""
        lines = [
            "AGENT NOTEBOOK (submitted via MCP by an external agent; supplements "
            "profile.yml, never overrides it - if the two conflict, profile.yml "
            "is the authority on network topology and policy)",
        ]
        for e in entries:
            author = f" ({e['author']})" if e["author"] else ""
            lines.append(f"  [{e['created_at']}]{author}: {e['text']}")
        return "\n".join(lines)
