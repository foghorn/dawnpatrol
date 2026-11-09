"""Keep a chat-completions conversation inside a fixed context window.

Local models (Ollama, llama.cpp, ...) have a hard ``num_ctx``. What a server
does with a prompt past it is its own business - Ollama can silently drop the
oldest messages, which here means the evidence bundle - so the provider has to
stay under it itself. Three measures, cheapest first:

1. Size each call's output budget to the room actually left, instead of
   always reserving the configured ``max_tokens``.
2. When the prompt passes the high-water mark, replace the oldest tool results
   with one-line stubs until it is back under the low-water mark. The system
   messages, the bundle (first user message), every assistant turn and the
   most recent results are never touched, so the conversation stays coherent
   and the model can re-run any tool it still needs. Trimming happens in one
   batch rather than a little every turn, because any change to the prompt
   invalidates the server's prefix cache from that point on.
3. If even that leaves too little room to answer, tell the model to stop
   investigating and submit (see :data:`WRAP_UP_MESSAGE`).

Token counts are estimated from characters, calibrated against the
``prompt_tokens`` the server reports after every call.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

#: Start trimming when the prompt alone passes this share of the window...
HIGH_WATER = 0.85
#: ...and trim down to this share.
LOW_WATER = 0.60
#: Below this much room for output, trimming has failed and the model is told
#: to wrap up. The largest single answers seen from local models are ~10k.
MIN_OUTPUT_TOKENS = 4096
#: Below this much room the call cannot usefully be made at all.
HARD_FLOOR_TOKENS = 1024
#: Slack for tokenizer/template overhead the estimate cannot see.
SAFETY_MARGIN_TOKENS = 512
#: Never remove the newest results; the model is most likely using them.
KEEP_RECENT_RESULTS = 3
#: Characters per token before the server has reported a real count. Measured
#: ~3.3 on DawnPatrol's JSON-heavy prompts; a lower guess errs toward trimming.
DEFAULT_CHARS_PER_TOKEN = 3.0

WRAP_UP_MESSAGE = (
    "The context window is nearly full. Do not call any more investigation "
    "tools. Call submit_analysis now with your complete analysis, based on "
    "what you have already established; record anything you could not finish "
    "checking in detection_gaps or data_quality_notes."
)


def _chars(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"), default=str))


@dataclass(slots=True)
class Plan:
    """What to do before the next call."""

    max_tokens: int
    #: Results replaced with stubs by this call to :meth:`ContextWindow.plan`.
    removed: int = 0
    #: The model should be told to submit now.
    wrap_up: bool = False
    #: Not even HARD_FLOOR_TOKENS of room - the call should not be made.
    exhausted: bool = False
    estimated_prompt_tokens: int = 0


@dataclass
class ContextWindow:
    limit_tokens: int
    max_output_tokens: int
    #: Character size of the tool definitions sent with every call.
    fixed_chars: int = 0
    high_water: float = HIGH_WATER
    low_water: float = LOW_WATER
    _chars_per_token: float = DEFAULT_CHARS_PER_TOKEN
    _last_prompt_tokens: int = 0
    _last_prompt_chars: int = 0
    total_removed: int = 0
    trims: int = 0
    peak_prompt_tokens: int = 0
    #: Positions already stubbed (the message list is append-only).
    _removed: set[int] = field(default_factory=set)

    # ----- measurement ------------------------------------------------------ #

    def _messages_chars(self, messages: list[dict[str, Any]]) -> int:
        return self.fixed_chars + sum(_chars(m) for m in messages)

    def record(self, messages: list[dict[str, Any]], prompt_tokens: int) -> None:
        """Calibrate from the server's count for the prompt just sent."""
        if prompt_tokens <= 0:
            return
        sent = self._messages_chars(messages)
        self._chars_per_token = max(1.0, sent / prompt_tokens)
        self._last_prompt_tokens = prompt_tokens
        self._last_prompt_chars = sent
        self.peak_prompt_tokens = max(self.peak_prompt_tokens, prompt_tokens)

    def estimate(self, messages: list[dict[str, Any]]) -> int:
        now = self._messages_chars(messages)
        if not self._last_prompt_tokens:
            return int(now / self._chars_per_token)
        delta = now - self._last_prompt_chars
        return max(0, int(self._last_prompt_tokens + delta / self._chars_per_token))

    # ----- planning --------------------------------------------------------- #

    def plan(self, messages: list[dict[str, Any]]) -> Plan:
        """Trim ``messages`` in place if needed and size the next call."""
        estimate = self.estimate(messages)
        removed = 0
        if estimate > self.high_water * self.limit_tokens:
            target = int(self.low_water * self.limit_tokens)
            removed = self._trim(messages, target, keep=KEEP_RECENT_RESULTS)
            if self._room(messages) < MIN_OUTPUT_TOKENS:
                # The recent results alone are too big: give up all but the newest.
                removed += self._trim(messages, target, keep=1)
            if removed:
                self.trims += 1
                self.total_removed += removed
                after = self.estimate(messages)
                log.info("context: removed %d old tool result(s), ~%d -> ~%d of %d tokens",
                         removed, estimate, after, self.limit_tokens)
                estimate = after

        room = self._room(messages)
        max_tokens = min(self.max_output_tokens, room)
        return Plan(
            max_tokens=max(max_tokens, 0),
            removed=removed,
            wrap_up=room < MIN_OUTPUT_TOKENS,
            exhausted=room < HARD_FLOOR_TOKENS,
            estimated_prompt_tokens=estimate,
        )

    def _room(self, messages: list[dict[str, Any]]) -> int:
        return self.limit_tokens - self.estimate(messages) - SAFETY_MARGIN_TOKENS

    def _trim(self, messages: list[dict[str, Any]], target_tokens: int, *, keep: int) -> int:
        from .base import SUBMIT_TOOL  # local: base imports nothing from here

        results = [i for i, m in enumerate(messages)
                   if m.get("role") == "tool"
                   and m.get("name") != SUBMIT_TOOL  # format corrections carry the schema
                   and i not in self._removed]
        candidates = results[:-keep] if keep else results
        if not candidates:
            return 0

        calls = _tool_call_args(messages)
        removed = 0
        for i in candidates:
            if self.estimate(messages) <= target_tokens:
                break
            msg = messages[i]
            call_id = msg.get("tool_call_id") or ""
            original = msg.get("content") or ""
            stub = (f"[Result removed to free context space: {len(original)} characters "
                    f"from {msg.get('name') or 'tool'}({calls.get(call_id, '')}). "
                    f"Call the tool again if you still need it.]")
            if len(stub) >= len(original):
                continue
            messages[i] = {**msg, "content": stub}
            self._removed.add(i)
            removed += 1
        return removed

    def summary(self) -> str:
        """Report note, or "" when nothing had to be done."""
        if not self.total_removed:
            return ""
        return (f"the analysis neared the model's {self.limit_tokens:,}-token context "
                f"window; {self.total_removed} older tool result(s) were removed from "
                f"its working context ({self.trims} trim(s)) - it could re-run any "
                f"query it still needed")


def _tool_call_args(messages: list[dict[str, Any]]) -> dict[str, str]:
    """tool_call_id -> short rendering of the arguments that produced it."""
    out: dict[str, str] = {}
    for m in messages:
        for call in m.get("tool_calls") or []:
            args = (call.get("function") or {}).get("arguments") or ""
            if not isinstance(args, str):
                args = json.dumps(args, default=str)
            out[call.get("id") or ""] = args if len(args) <= 200 else args[:197] + "..."
    return out
