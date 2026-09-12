"""Spend ceilings for the model stage.

A run that trips a ceiling degrades to a statistics-only report rather than
producing nothing. A report that says "the analysis stage was cut short" is
useful; a missing report is not.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .errors import BudgetExceeded
from .models import TokenUsage

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Budget:
    max_cost_usd: float = 3.00
    max_turns: int = 30
    max_tool_calls: int = 25
    tripped: str = ""

    def check(self, usage: TokenUsage) -> None:
        if self.max_cost_usd > 0 and usage.cost_usd >= self.max_cost_usd:
            self.tripped = (
                f"cost ceiling reached: ${usage.cost_usd:.2f} of "
                f"${self.max_cost_usd:.2f} after {usage.calls} model calls"
            )
            raise BudgetExceeded(self.tripped)

    def describe(self) -> str:
        return (f"max ${self.max_cost_usd:.2f}, {self.max_turns} turns, "
                f"{self.max_tool_calls} tool calls")
