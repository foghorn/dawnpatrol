"""Model provider contract.

Providers are plugins like everything else, so a local OpenAI-compatible server
is a drop-in alternative to a hosted API. The harness hands a provider a system
prompt, an evidence bundle, and a tool surface; the provider owns its own
request shape and agent loop and returns a uniform result.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import AISettings
from ..models import TokenUsage

log = logging.getLogger(__name__)

#: Name of the terminal tool. Using a tool to return the final answer - rather
#: than provider-specific structured output - keeps every provider on the same
#: code path and works on servers with no JSON-schema response support.
SUBMIT_TOOL = "submit_analysis"


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]
    #: When true, calling this tool ends the loop.
    terminal: bool = False


@dataclass(slots=True)
class ToolCallLog:
    name: str
    arguments: dict[str, Any]
    ok: bool
    detail: str = ""


@dataclass(slots=True)
class AgentRun:
    """Uniform result regardless of provider."""

    analysis: dict[str, Any] | None = None
    usage: TokenUsage = field(default_factory=TokenUsage)
    tool_calls: list[ToolCallLog] = field(default_factory=list)
    turns: int = 0
    stop_reason: str = ""
    error: str | None = None
    transcript_note: str = ""

    @property
    def ok(self) -> bool:
        return self.analysis is not None and self.error is None


class Provider(ABC):
    name: str = ""
    requires_env: frozenset[str] = frozenset()
    #: USD per million tokens, for cost accounting. Zero means "unknown/free".
    price_input_per_mtok: float = 0.0
    price_output_per_mtok: float = 0.0
    price_cache_read_per_mtok: float = 0.0
    #: A cache write is real, billed usage distinct from a cache read (often
    #: priced *above* base input, e.g. 1.25x - "populating" the cache costs
    #: more than reading from it). Zero by default like the others; a
    #: provider that never reports cache_write_tokens (most don't) simply
    #: never multiplies against it.
    price_cache_write_per_mtok: float = 0.0

    def __init__(self, settings: AISettings) -> None:
        self.settings = settings

    @abstractmethod
    def run_agent(
        self,
        *,
        system_static: str,
        system_context: str,
        user_message: str,
        tools: list[ToolSpec],
        max_turns: int,
        on_turn: Callable[[TokenUsage], None] | None = None,
    ) -> AgentRun:
        """Drive the tool loop until the terminal tool is called or limits hit.

        ``system_static`` and ``system_context`` are split so providers that
        support prompt caching can place a breakpoint between them; both are
        byte-stable across runs.
        """

    def estimate_cost(self, usage: TokenUsage) -> float:
        return (
            usage.input_tokens / 1_000_000 * self.price_input_per_mtok
            + usage.output_tokens / 1_000_000 * self.price_output_per_mtok
            + usage.cache_read_tokens / 1_000_000 * self.price_cache_read_per_mtok
            + usage.cache_write_tokens / 1_000_000 * self.price_cache_write_per_mtok
        )

    def available(self) -> tuple[bool, str]:
        """Whether this provider can actually run (SDK installed, key present)."""
        return True, ""

    def __repr__(self) -> str:
        return f"<Provider {self.name}>"
