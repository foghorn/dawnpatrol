"""OpenAI's native ``/v1/responses`` API - not the ``/v1/chat/completions``
shape ``openai_compatible.py`` targets.

Built after a live trial (see README's "Model choice and report quality")
against ``gpt-5.6-sol`` found that ``openai_compatible`` needed this
reasoning-tier model's reasoning disabled entirely (its designator's own
``_REASONING_EFFORT=none``) just to unlock tool calling on
``/v1/chat/completions`` - a real capability loss, not a config quirk.
``/v1/responses`` is OpenAI's own answer to that: tool calling and reasoning
work together natively there, confirmed live before writing this file (a
tool call at the API's default "medium" effort, no workaround needed).

Use this provider for OpenAI's own models; use ``openai_compatible`` for
local, self-hosted, or proxied backends (Ollama, LM Studio, vLLM, LiteLLM) -
including ones that happen to route to OpenAI models, since a proxy's own
compatibility shape is what matters there, not the upstream model.

Set ``DAWNPATROL_AI_<NAME>_PROVIDER=openai`` and
``DAWNPATROL_AI_<NAME>_API_KEY`` to an OpenAI key, for whichever designator
name this config lives under (see ``config.py``'s ``_load_ai_profiles``).
``DAWNPATROL_AI_<NAME>_BASE_URL`` defaults to ``https://api.openai.com`` and
rarely needs setting - it exists for an OpenAI-compatible gateway that
specifically implements ``/v1/responses`` too, not for arbitrary local
servers (those almost never implement this endpoint; use
``openai_compatible`` for them).

Two things confirmed live and encoded here rather than left to guesswork:

* ``reasoning.effort`` reuses this designator's ``_EFFORT`` unchanged - this
  model's accepted values (confirmed via its own error text: "Supported
  values are: 'none', 'low', 'medium', 'high', 'xhigh', and 'max'") are
  exactly this project's existing five-tier scale, plus "none".
* ``temperature`` is never sent - reasoning models reject it outright
  ("Unsupported parameter: 'temperature' is not supported with this
  model"), confirmed live, so there is nothing to make configurable here.

``store`` is always sent as ``false``. The Responses API defaults to
server-side conversation retention; DawnPatrol's prompts carry internal
IPs, hostnames, and account names, which is exactly the kind of data this
project treats carefully everywhere else (see ``adjudicate.scan_for_secrets``,
the MCP surface's opt-in gates). Retention is OpenAI's to control, not this
provider's default to leave on.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import httpx

from ..models import TokenUsage
from .base import SUBMIT_TOOL, AgentRun, Provider, ToolCallLog, ToolSpec

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.openai.com"


class OpenAIProvider(Provider):
    name = "openai"
    requires_env = frozenset()

    def __init__(self, settings) -> None:
        super().__init__(settings)
        # Left at 0.0 ("unknown/free") for any model whose real published
        # rate hasn't been set on this designator's config - guessing a
        # number would be worse than admitting it's unknown. Real usage is
        # billed by OpenAI regardless of what these are set to; treat the
        # account's own usage dashboard as the source of truth for a model
        # not priced below.
        self.price_input_per_mtok = settings.price_input_per_mtok
        self.price_output_per_mtok = settings.price_output_per_mtok
        self.price_cache_read_per_mtok = settings.price_cache_read_per_mtok
        self.price_cache_write_per_mtok = settings.price_cache_write_per_mtok

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Overrides the base formula, which assumes Anthropic's convention
        (``input_tokens`` already *excludes* cached tokens, reported
        separately and additively). OpenAI's ``/v1/responses`` does the
        opposite - confirmed live by resending an identical long prefix and
        watching ``input_tokens`` stay ~constant while ``cached_tokens``
        jumped to nearly the same value: ``input_tokens`` is the TOTAL
        prompt size, and ``cached_tokens`` is a *subset* of it, not an
        addition. Using the base formula unmodified here would double-bill
        every cached token: once at the full input rate as part of
        ``input_tokens``, again at the cache-read rate. ``cache_write_tokens``
        by contrast IS additive - confirmed live in the same test, a token
        both counted in ``input_tokens`` and written to cache for the first
        time billed the normal input rate plus a separate write surcharge -
        so it is simply added on top, same as the base formula's treatment.
        """
        fresh_input = max(0, usage.input_tokens - usage.cache_read_tokens)
        return (
            fresh_input / 1_000_000 * self.price_input_per_mtok
            + usage.cache_read_tokens / 1_000_000 * self.price_cache_read_per_mtok
            + usage.output_tokens / 1_000_000 * self.price_output_per_mtok
            + usage.cache_write_tokens / 1_000_000 * self.price_cache_write_per_mtok
        )

    @property
    def endpoint(self) -> str:
        base = (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        return f"{base}/responses"

    def available(self) -> tuple[bool, str]:
        if not self.settings.api_key:
            return False, "no API key set for the active AI config"
        return True, ""

    @staticmethod
    def _tool_defs(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        # Flat shape, unlike chat/completions' nested {"function": {...}} -
        # confirmed live. No "strict" - DawnPatrol's tool schemas have
        # optional properties not listed in "required", which strict mode
        # (every property mandatory, additionalProperties:false throughout)
        # does not allow.
        return [
            {"type": "function", "name": t.name, "description": t.description,
             "parameters": t.parameters}
            for t in tools
        ]

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
        run = AgentRun()
        by_name = {t.name: t for t in tools}

        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {self.settings.api_key.get()}"}

        # Stable prefix first (role:"system" items work directly in `input`,
        # confirmed live) so an automatic prompt-cache hit on this prefix is
        # possible on turn 2+, the same shape as the other two providers.
        input_items: list[dict[str, Any]] = [
            {"role": "system", "content": system_static},
            {"role": "system", "content": system_context},
            {"role": "user", "content": user_message},
        ]
        with httpx.Client(timeout=self.settings.timeout_seconds, headers=headers,
                          verify=self.settings.verify_tls) as client:
            for turn in range(1, max_turns + 1):
                run.turns = turn
                payload: dict[str, Any] = {
                    "model": self.settings.model,
                    "input": input_items,
                    "tools": self._tool_defs(tools),
                    "tool_choice": "auto",
                    "max_output_tokens": self.settings.max_tokens,
                    "reasoning": {"effort": self.settings.effort},
                    "store": False,
                }

                try:
                    resp = client.post(self.endpoint, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPStatusError as exc:
                    run.error = (f"HTTP {exc.response.status_code}: "
                                 f"{exc.response.text[:300]}")
                    return run
                except Exception as exc:  # noqa: BLE001
                    run.error = f"{type(exc).__name__}: {exc}"
                    return run

                if data.get("error"):
                    run.error = str(data["error"].get("message") or data["error"])
                    return run

                usage = _usage_from(data)
                usage.cost_usd = self.estimate_cost(usage)
                run.usage.add(usage)
                if on_turn is not None:
                    on_turn(run.usage)

                run.stop_reason = data.get("status") or ""
                output = data.get("output") or []

                calls: list[dict[str, Any]] = []
                for item in output:
                    itype = item.get("type")
                    if itype == "reasoning":
                        # Encrypted, model-internal - confirmed live that
                        # dropping it (not echoing it back into the next
                        # turn's input) does not affect correctness.
                        continue
                    if itype == "function_call":
                        input_items.append(item)
                        calls.append(item)
                    elif itype == "message":
                        input_items.append(item)

                if not calls:
                    text = _output_text(output)
                    parsed = _try_parse_json(text)
                    if parsed is not None and "findings" in parsed:
                        run.analysis = parsed
                        run.transcript_note = (
                            f"model returned the analysis as content rather than "
                            f"calling {SUBMIT_TOOL}"
                        )
                        return run
                    run.error = (f"model stopped without calling {SUBMIT_TOOL} "
                                 f"(status={run.stop_reason})")
                    return run

                for call in calls:
                    tool_name = call.get("name") or ""
                    call_id = call.get("call_id") or ""
                    args = _try_parse_json(call.get("arguments") or "{}") or {}
                    spec = by_name.get(tool_name)

                    if spec is None:
                        input_items.append(_call_output(call_id, f"unknown tool {tool_name}"))
                        run.tool_calls.append(ToolCallLog(tool_name, args, False, "unknown"))
                        continue
                    if spec.terminal:
                        run.analysis = args
                        run.tool_calls.append(ToolCallLog(tool_name, {}, True, "terminal"))
                        return run
                    try:
                        result = spec.handler(args)
                        text = result if isinstance(result, str) else json.dumps(
                            result, default=str)[:20000]
                        input_items.append(_call_output(call_id, text))
                        run.tool_calls.append(ToolCallLog(tool_name, args, True))
                    except Exception as exc:  # noqa: BLE001
                        detail = f"{type(exc).__name__}: {exc}"
                        input_items.append(_call_output(call_id, f"ERROR: {detail}"))
                        run.tool_calls.append(ToolCallLog(tool_name, args, False, detail))

        run.error = f"reached the {max_turns}-turn limit without a final analysis"
        return run


def _call_output(call_id: str, output: str) -> dict[str, Any]:
    return {"type": "function_call_output", "call_id": call_id, "output": output}


def _output_text(output: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in output:
        if item.get("type") != "message":
            continue
        for block in item.get("content") or []:
            if block.get("type") == "output_text":
                parts.append(block.get("text") or "")
    return "\n".join(parts)


def _try_parse_json(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                parsed = json.loads(text[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _usage_from(data: dict[str, Any]) -> TokenUsage:
    u = data.get("usage") or {}
    in_details = u.get("input_tokens_details") or {}
    return TokenUsage(
        input_tokens=int(u.get("input_tokens") or 0),
        output_tokens=int(u.get("output_tokens") or 0),
        cache_read_tokens=int(in_details.get("cached_tokens") or 0),
        cache_write_tokens=int(in_details.get("cache_write_tokens") or 0),
        calls=1,
    )
