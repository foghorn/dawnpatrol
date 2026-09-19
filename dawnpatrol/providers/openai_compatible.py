"""OpenAI-compatible chat-completions provider.

Targets any server speaking ``/v1/chat/completions`` with function calling:
Ollama, LM Studio, vLLM, llama.cpp, LiteLLM, Open-WebUI, or the OpenAI API
itself. Uses httpx rather than the ``openai`` package because local servers vary
in small ways and a thin client is easier to accommodate than a strict one.

Set ``DAWNPATROL_AI_PROVIDER=openai_compatible`` and ``DAWNPATROL_AI_BASE_URL`` to
the server root (the ``/v1`` suffix is added when absent).

Two settings exist only because newer OpenAI reasoning models (the gpt-5.x
line, confirmed live against ``gpt-5.6-sol``) are not drop-in compatible with
older OpenAI-compatible servers on this same endpoint shape:

* ``DAWNPATROL_AI_MAX_TOKENS_PARAM`` (default ``max_tokens``) - these models
  reject ``max_tokens`` outright ("Unsupported parameter... Use
  'max_completion_tokens' instead"). Most other backends on this endpoint
  (Ollama, LM Studio, vLLM, llama.cpp, LiteLLM, older OpenAI models) still
  expect ``max_tokens`` and may not recognize the newer name, so this is
  configurable per deployment rather than guessed or auto-detected.
* ``DAWNPATROL_AI_REASONING_EFFORT`` (unset by default) - these models refuse
  function tools on ``/v1/chat/completions`` entirely unless this is
  explicitly ``none`` ("Function tools with reasoning_effort are not
  supported... use /v1/responses or set reasoning_effort to 'none'" is the
  server's own error text). Since this pipeline requires tool calling, a
  reasoning-tier model needs this set to ``none`` to be usable here at all -
  which also means it runs with its reasoning effectively disabled for this
  task, not a free capability upgrade over a non-reasoning model of the same
  family. Omitted from the payload entirely when unset, since most
  non-OpenAI servers do not recognize this field.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import httpx

from ..models import TokenUsage
from ..secrets import read_bool, read_env, read_float, read_int
from .base import SUBMIT_TOOL, AgentRun, Provider, ToolCallLog, ToolSpec

log = logging.getLogger(__name__)


class OpenAICompatibleProvider(Provider):
    name = "openai_compatible"
    requires_env = frozenset({"DAWNPATROL_AI_BASE_URL"})

    def __init__(self, settings) -> None:
        super().__init__(settings)
        # Local models are usually free; hosted ones can be priced via env.
        self.price_input_per_mtok = read_float("DAWNPATROL_AI_PRICE_IN", 0.0)
        self.price_output_per_mtok = read_float("DAWNPATROL_AI_PRICE_OUT", 0.0)
        self.price_cache_read_per_mtok = read_float("DAWNPATROL_AI_PRICE_CACHE_READ", 0.0)
        self.price_cache_write_per_mtok = read_float("DAWNPATROL_AI_PRICE_CACHE_WRITE", 0.0)
        self.max_tokens_param = (
            read_env("DAWNPATROL_AI_MAX_TOKENS_PARAM", "max_tokens") or "max_tokens"
        )
        self.reasoning_effort = read_env("DAWNPATROL_AI_REASONING_EFFORT", "") or ""

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Same fix as openai_provider.py's override, for the same reason:
        this endpoint's `prompt_tokens` is the TOTAL prompt size, inclusive
        of any cached portion (`cached_tokens` is a subset, not an additive
        count) whenever the server behind this provider is OpenAI itself or
        a proxy faithfully reporting OpenAI's own usage shape (LiteLLM, for
        one). The base formula assumes Anthropic's convention instead
        (input_tokens already excludes cache reads) and would double-bill
        every cached token here without this override."""
        fresh_input = max(0, usage.input_tokens - usage.cache_read_tokens)
        return (
            fresh_input / 1_000_000 * self.price_input_per_mtok
            + usage.cache_read_tokens / 1_000_000 * self.price_cache_read_per_mtok
            + usage.output_tokens / 1_000_000 * self.price_output_per_mtok
            + usage.cache_write_tokens / 1_000_000 * self.price_cache_write_per_mtok
        )

    @property
    def endpoint(self) -> str:
        base = (self.settings.base_url or "").rstrip("/")
        if not base:
            return ""
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        return f"{base}/chat/completions"

    def available(self) -> tuple[bool, str]:
        if not self.settings.base_url:
            return False, "DAWNPATROL_AI_BASE_URL is not set"
        return True, ""

    @staticmethod
    def _tool_defs(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {"type": "function",
             "function": {"name": t.name, "description": t.description,
                          "parameters": t.parameters}}
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
        if not self.endpoint:
            run.error = "no base URL configured"
            return run

        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key.get()}"

        messages: list[dict[str, Any]] = [
            # Two system messages keep the stable prefix separable, which some
            # gateways use for caching; servers that do not care simply see two.
            {"role": "system", "content": system_static},
            {"role": "system", "content": system_context},
            {"role": "user", "content": user_message},
        ]
        timeout = read_int("DAWNPATROL_AI_TIMEOUT", 300)
        verify = read_bool("DAWNPATROL_AI_VERIFY_TLS", True)

        with httpx.Client(timeout=timeout, headers=headers, verify=verify) as client:
            for turn in range(1, max_turns + 1):
                run.turns = turn
                payload: dict[str, Any] = {
                    "model": self.settings.model,
                    "messages": messages,
                    "tools": self._tool_defs(tools),
                    "tool_choice": "auto",
                    self.max_tokens_param: self.settings.max_tokens,
                    "stream": False,
                }
                if self.settings.temperature is not None:
                    payload["temperature"] = self.settings.temperature
                if self.reasoning_effort:
                    payload["reasoning_effort"] = self.reasoning_effort

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

                usage = _usage_from(data)
                usage.cost_usd = self.estimate_cost(usage)
                run.usage.add(usage)
                if on_turn is not None:
                    on_turn(run.usage)

                choices = data.get("choices") or []
                if not choices:
                    run.error = "server returned no choices"
                    return run
                message = choices[0].get("message") or {}
                run.stop_reason = choices[0].get("finish_reason") or ""
                tool_calls = message.get("tool_calls") or []

                messages.append({
                    "role": "assistant",
                    "content": message.get("content") or "",
                    **({"tool_calls": tool_calls} if tool_calls else {}),
                })

                if not tool_calls:
                    # Some local models emit the final JSON as content instead of
                    # calling the tool. Accept that rather than discarding a
                    # complete analysis over a protocol detail.
                    parsed = _try_parse_json(message.get("content") or "")
                    if parsed is not None and "findings" in parsed:
                        run.analysis = parsed
                        run.transcript_note = (
                            f"model returned the analysis as content rather than "
                            f"calling {SUBMIT_TOOL}"
                        )
                        return run
                    run.error = (f"model stopped without calling {SUBMIT_TOOL} "
                                 f"(finish_reason={run.stop_reason})")
                    return run

                for call in tool_calls:
                    fn = call.get("function") or {}
                    tool_name = fn.get("name") or ""
                    call_id = call.get("id") or tool_name
                    args = _try_parse_json(fn.get("arguments") or "{}") or {}
                    spec = by_name.get(tool_name)

                    if spec is None:
                        messages.append(_tool_message(call_id, tool_name,
                                                      f"unknown tool {tool_name}"))
                        run.tool_calls.append(ToolCallLog(tool_name, args, False, "unknown"))
                        continue
                    if spec.terminal:
                        run.analysis = args
                        run.tool_calls.append(ToolCallLog(tool_name, {}, True, "terminal"))
                        return run
                    try:
                        output = spec.handler(args)
                        text = output if isinstance(output, str) else json.dumps(
                            output, default=str)[:20000]
                        messages.append(_tool_message(call_id, tool_name, text))
                        run.tool_calls.append(ToolCallLog(tool_name, args, True))
                    except Exception as exc:  # noqa: BLE001
                        detail = f"{type(exc).__name__}: {exc}"
                        messages.append(_tool_message(call_id, tool_name, f"ERROR: {detail}"))
                        run.tool_calls.append(ToolCallLog(tool_name, args, False, detail))

        run.error = f"reached the {max_turns}-turn limit without a final analysis"
        return run


def _tool_message(call_id: str, name: str, content: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "name": name, "content": content}


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
    details = u.get("prompt_tokens_details") or {}
    return TokenUsage(
        input_tokens=int(u.get("prompt_tokens") or 0),
        output_tokens=int(u.get("completion_tokens") or 0),
        cache_read_tokens=int(details.get("cached_tokens") or 0),
        cache_write_tokens=int(details.get("cache_write_tokens") or 0),
        calls=1,
    )
