"""Anthropic provider.

Uses a manual tool loop rather than the SDK's tool runner, because the harness
needs per-turn budget checks, cost accounting, and a terminal-tool break - and
because keeping the loop shape identical to the OpenAI-compatible provider makes
both easy to reason about.

Prompt caching matters here: the system prompt and the site profile are
byte-stable across runs, so a cache breakpoint after the profile turns ~10k
tokens of daily input into a cache read. Nothing volatile (timestamps, run ids,
counts) may appear before that breakpoint or the cache silently never hits.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from ..models import TokenUsage
from .base import SUBMIT_TOOL, AgentRun, Provider, ToolCallLog, ToolSpec

log = logging.getLogger(__name__)

#: Published per-MTok pricing, used for the run's cost ceiling. A designator
#: whose model isn't listed here - or whose real rate has drifted from it -
#: can override via that designator's own _PRICE_IN/_OUT/_PRICE_CACHE_READ.
_PRICING = {
    "claude-opus-5": (5.0, 25.0, 0.50),
    "claude-opus-4-8": (5.0, 25.0, 0.50),
    "claude-sonnet-5": (2.0, 10.0, 0.20),
    "claude-haiku-4-5": (1.0, 5.0, 0.10),
    "claude-fable-5-1": (10.0, 50.0, 1.00),
}


class AnthropicProvider(Provider):
    name = "anthropic"
    requires_env = frozenset()

    def __init__(self, settings) -> None:
        super().__init__(settings)
        pin, pout, pcache = _PRICING.get(settings.model, (5.0, 25.0, 0.50))
        self.price_input_per_mtok = settings.price_input_per_mtok or pin
        self.price_output_per_mtok = settings.price_output_per_mtok or pout
        self.price_cache_read_per_mtok = settings.price_cache_read_per_mtok or pcache
        self.price_cache_write_per_mtok = settings.price_cache_write_per_mtok

    def available(self) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "the 'anthropic' package is not installed (pip install anthropic)"
        if not self.settings.api_key:
            return False, "no API key set for the active AI config"
        return True, ""

    # ----- tool translation -------------------------------------------------- #

    @staticmethod
    def _tool_defs(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]

    # ----- the loop ----------------------------------------------------------- #

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
        import anthropic

        run = AgentRun()
        by_name = {t.name: t for t in tools}
        client = anthropic.Anthropic(api_key=self.settings.api_key.get() or None)

        # Stable prefix first, cache breakpoint at the end of the profile block.
        system_blocks: list[dict[str, Any]] = [
            {"type": "text", "text": system_static},
            {"type": "text", "text": system_context,
             "cache_control": {"type": "ephemeral"}},
        ]
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

        request: dict[str, Any] = {
            "model": self.settings.model,
            "max_tokens": self.settings.max_tokens,
            "system": system_blocks,
            "tools": self._tool_defs(tools),
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": self.settings.effort},
        }
        if self.settings.task_budget_tokens >= 20000:
            request["output_config"]["task_budget"] = {
                "type": "tokens", "total": self.settings.task_budget_tokens,
            }

        use_beta = self.settings.refusal_fallback
        for turn in range(1, max_turns + 1):
            run.turns = turn
            try:
                message = self._create(client, request, messages, use_beta)
            except _BetaUnsupported as exc:
                # The server rejected the beta parameters; retry once on the
                # standard path rather than failing the whole run over them.
                log.warning("disabling refusal fallback: %s", exc)
                use_beta = False
                try:
                    message = self._create(client, request, messages, False)
                except Exception as inner:  # noqa: BLE001
                    run.error = f"{type(inner).__name__}: {inner}"
                    return run
            except Exception as exc:  # noqa: BLE001
                run.error = f"{type(exc).__name__}: {exc}"
                return run

            usage = _usage_from(message)
            usage.cost_usd = self.estimate_cost(usage)
            run.usage.add(usage)
            if on_turn is not None:
                on_turn(run.usage)

            run.stop_reason = getattr(message, "stop_reason", "") or ""
            if run.stop_reason == "refusal":
                details = getattr(message, "stop_details", None)
                run.error = f"model declined to answer ({getattr(details, 'category', 'unknown')})"
                return run

            # Echo content back unchanged - thinking blocks must round-trip intact.
            messages.append({"role": "assistant", "content": message.content})

            tool_uses = [b for b in message.content if getattr(b, "type", "") == "tool_use"]
            if not tool_uses:
                run.error = run.error or (
                    f"model stopped without calling {SUBMIT_TOOL} "
                    f"(stop_reason={run.stop_reason})"
                )
                return run

            results: list[dict[str, Any]] = []
            for block in tool_uses:
                spec = by_name.get(block.name)
                args = block.input if isinstance(block.input, dict) else {}
                if spec is None:
                    results.append(_tool_result(block.id, f"unknown tool {block.name}", True))
                    run.tool_calls.append(ToolCallLog(block.name, args, False, "unknown tool"))
                    continue
                if spec.terminal:
                    run.analysis = args
                    run.tool_calls.append(ToolCallLog(block.name, {}, True, "terminal"))
                    return run
                try:
                    output = spec.handler(args)
                    payload = output if isinstance(output, str) else json.dumps(
                        output, default=str)[:20000]
                    results.append(_tool_result(block.id, payload, False))
                    run.tool_calls.append(ToolCallLog(block.name, args, True))
                except Exception as exc:  # noqa: BLE001 - tool errors go back to the model
                    detail = f"{type(exc).__name__}: {exc}"
                    results.append(_tool_result(block.id, detail, True))
                    run.tool_calls.append(ToolCallLog(block.name, args, False, detail))

            # All tool_results must arrive in ONE user message, or the model
            # silently learns to stop making parallel calls.
            messages.append({"role": "user", "content": results})

        run.error = f"reached the {max_turns}-turn limit without a final analysis"
        return run

    def _create(self, client, request: dict[str, Any],
                messages: list[dict[str, Any]], use_beta: bool):
        import anthropic

        payload = dict(request, messages=messages)
        if use_beta:
            payload["betas"] = ["server-side-fallback-2026-07-01"]
            payload["fallbacks"] = "default"
            try:
                with client.beta.messages.stream(**payload) as stream:
                    return stream.get_final_message()
            except (TypeError, anthropic.BadRequestError) as exc:
                raise _BetaUnsupported(str(exc)) from exc
        with client.messages.stream(**payload) as stream:
            return stream.get_final_message()


class _BetaUnsupported(Exception):
    """The server or SDK rejected the optional beta parameters."""


def _tool_result(tool_use_id: str, content: str, is_error: bool) -> dict[str, Any]:
    block: dict[str, Any] = {
        "type": "tool_result", "tool_use_id": tool_use_id, "content": content,
    }
    if is_error:
        block["is_error"] = True
    return block


def _usage_from(message) -> TokenUsage:
    u = getattr(message, "usage", None)
    if u is None:
        return TokenUsage(calls=1)
    return TokenUsage(
        input_tokens=getattr(u, "input_tokens", 0) or 0,
        output_tokens=getattr(u, "output_tokens", 0) or 0,
        cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
        cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
        calls=1,
    )
