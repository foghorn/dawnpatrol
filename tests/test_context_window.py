"""Context management for small-window models (providers/context_window.py)."""

from __future__ import annotations

import json

import httpx

from dawnpatrol.config import AISettings, _read_context_tokens
from dawnpatrol.providers.base import SUBMIT_TOOL, ToolSpec
from dawnpatrol.providers.context_window import (
    KEEP_RECENT_RESULTS,
    SAFETY_MARGIN_TOKENS,
    WRAP_UP_MESSAGE,
    ContextWindow,
)
from dawnpatrol.providers.openai_compatible import OpenAICompatibleProvider, _cap

# --------------------------------------------------------------------------- #
# ContextWindow on its own
# --------------------------------------------------------------------------- #


def _conversation(n_results: int, result_chars: int = 4000) -> list[dict]:
    msgs = [
        {"role": "system", "content": "S" * 1000},
        {"role": "system", "content": "C" * 1000},
        {"role": "user", "content": "BUNDLE" * 500},
    ]
    for i in range(n_results):
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [{"id": f"c{i}", "type": "function",
                                     "function": {"name": "query_events",
                                                  "arguments": json.dumps({"q": i})}}]})
        msgs.append({"role": "tool", "tool_call_id": f"c{i}", "name": "query_events",
                     "content": f"R{i}:" + "x" * result_chars})
    return msgs


def _window(limit: int, max_output: int = 8000) -> ContextWindow:
    w = ContextWindow(limit_tokens=limit, max_output_tokens=max_output)
    w._chars_per_token = 1.0  # makes the arithmetic in these tests exact enough
    return w


def test_small_conversation_is_untouched_and_gets_full_output_budget():
    msgs = _conversation(2)
    before = json.dumps(msgs)
    plan = _window(100_000).plan(msgs)
    assert plan.removed == 0 and not plan.wrap_up
    assert plan.max_tokens == 8000
    assert json.dumps(msgs) == before


def test_output_budget_shrinks_to_the_room_left():
    msgs = _conversation(1)
    w = _window(100_000, max_output=99_000)
    est = w.estimate(msgs)
    assert w.plan(msgs).max_tokens == 100_000 - est - SAFETY_MARGIN_TOKENS


def test_trims_oldest_results_down_to_low_water_and_keeps_the_rest():
    msgs = _conversation(10)
    w = _window(int(_window(1).estimate(msgs) / 0.9))  # start at ~90% of the window
    plan = w.plan(msgs)
    assert plan.removed > 0
    assert w.estimate(msgs) <= 0.60 * w.limit_tokens
    tool_msgs = [m for m in msgs if m["role"] == "tool"]
    stubbed = [m for m in tool_msgs if m["content"].startswith("[Result removed")]
    # oldest first, newest always kept
    assert tool_msgs[:len(stubbed)] == stubbed
    assert all(not m["content"].startswith("[Result removed")
               for m in tool_msgs[-KEEP_RECENT_RESULTS:])
    # system prompt, bundle and assistant turns untouched
    assert msgs[0]["content"] == "S" * 1000 and msgs[2]["content"] == "BUNDLE" * 500
    assert sum(1 for m in msgs if m["role"] == "assistant") == 10


def test_stub_names_the_tool_and_its_arguments():
    msgs = _conversation(6)
    w = _window(int(_window(1).estimate(msgs) / 0.9))
    w.plan(msgs)
    stub = next(m for m in msgs if m["role"] == "tool")["content"]
    assert "query_events" in stub and '{"q": 0}' in stub
    assert "Call the tool again" in stub
    assert w.summary().startswith("the analysis neared")


def test_format_corrections_are_never_removed():
    msgs = _conversation(6)
    msgs.insert(4, {"role": "tool", "tool_call_id": "s", "name": SUBMIT_TOOL,
                    "content": "SCHEMA " * 2000})
    w = _window(int(_window(1).estimate(msgs) / 0.9))
    w.plan(msgs)
    assert msgs[4]["content"] == "SCHEMA " * 2000


def test_a_tool_name_reused_as_call_id_does_not_block_later_trims():
    """Servers without call ids fall back to the tool name; positions, not ids,
    must decide what was already trimmed."""
    msgs = _conversation(8)
    for m in msgs:
        if m["role"] == "tool":
            m["tool_call_id"] = "query_events"
    w = _window(int(_window(1).estimate(msgs) / 0.9))
    assert w.plan(msgs).removed >= 2


def test_recent_results_are_given_up_when_they_alone_fill_the_window():
    msgs = _conversation(3, result_chars=20000)  # only "recent" results exist
    w = _window(int(_window(1).estimate(msgs) / 0.97))  # too little room to answer
    plan = w.plan(msgs)
    assert plan.removed == 2 and not plan.wrap_up
    assert not msgs[-1]["content"].startswith("[Result removed")  # newest kept


def test_wrap_up_when_trimming_cannot_make_room():
    msgs = _conversation(0)  # nothing removable; the bundle alone is large
    w = _window(int(w_est := _window(1).estimate(msgs)) + 3000)
    plan = w.plan(msgs)
    assert plan.wrap_up and not plan.exhausted
    assert plan.max_tokens < 4096
    assert w_est > 0


def test_exhausted_when_no_room_at_all():
    msgs = _conversation(0)
    w = _window(_window(1).estimate(msgs) + 600)
    assert w.plan(msgs).exhausted


def test_calibrates_from_reported_prompt_tokens():
    msgs = _conversation(2)
    w = ContextWindow(limit_tokens=100_000, max_output_tokens=1000)
    chars = w._messages_chars(msgs)
    w.record(msgs, chars // 4)  # server says 4 chars per token
    assert abs(w.estimate(msgs) - chars // 4) <= 1
    msgs.append({"role": "tool", "tool_call_id": "z", "name": "t", "content": "y" * 4000})
    grown = w.estimate(msgs)
    assert 1000 <= grown - chars // 4 <= 1100


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #


def test_context_tokens_setting(monkeypatch):
    monkeypatch.setenv("X_CTX", "auto")
    assert _read_context_tokens("X_CTX") == -1
    monkeypatch.setenv("X_CTX", "73728")
    assert _read_context_tokens("X_CTX") == 73728
    monkeypatch.delenv("X_CTX")
    assert _read_context_tokens("X_CTX") == 0


# --------------------------------------------------------------------------- #
# the provider loop
# --------------------------------------------------------------------------- #

_RealClient = httpx.Client


def _provider(monkeypatch, handler, **overrides) -> OpenAICompatibleProvider:
    settings = AISettings(provider="openai_compatible", base_url="http://test.local",
                          model="m", max_tokens=32000)
    for k, v in overrides.items():
        setattr(settings, k, v)
    monkeypatch.setattr(
        "dawnpatrol.providers.openai_compatible.httpx.Client",
        lambda **kw: _RealClient(transport=httpx.MockTransport(handler)),
    )
    return OpenAICompatibleProvider(settings)


def _tools(result: str = "r") -> list[ToolSpec]:
    return [
        ToolSpec(name="query_events", description="q", parameters={"type": "object"},
                 handler=lambda args: result),
        ToolSpec(name=SUBMIT_TOOL, description="s", parameters={"type": "object"},
                 handler=lambda args: None, terminal=True),
    ]


def _reply(name: str, call_id: str, prompt_tokens: int, args: str = "{}") -> dict:
    return {
        "choices": [{"finish_reason": "tool_calls", "message": {
            "content": None,
            "tool_calls": [{"id": call_id, "type": "function",
                            "function": {"name": name, "arguments": args}}]}}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 10},
    }


def _scripted(replies: list[dict], seen: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json=replies[len(seen) - 1])
    return handler


def test_context_management_off_by_default_sends_configured_max_tokens(monkeypatch):
    seen: list[dict] = []
    replies = [_reply(SUBMIT_TOOL, "1", 50, '{"findings": []}')]
    p = _provider(monkeypatch, _scripted(replies, seen))
    run = p.run_agent(system_static="s", system_context="c", user_message="u",
                      tools=_tools(), max_turns=3)
    assert run.ok and run.context_note == ""
    assert seen[0]["max_tokens"] == 32000


def test_output_budget_is_capped_by_the_window(monkeypatch):
    seen: list[dict] = []
    replies = [_reply(SUBMIT_TOOL, "1", 50, '{"findings": []}')]
    p = _provider(monkeypatch, _scripted(replies, seen), context_tokens=20000)
    assert p.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3).ok
    assert seen[0]["max_tokens"] < 20000


def test_old_results_are_trimmed_in_the_next_request(monkeypatch):
    seen: list[dict] = []
    big = "x" * 30000
    # Server-reported prompt sizes climb toward the 40k window.
    replies = ([_reply("query_events", f"c{i}", 8000 + 9000 * i, json.dumps({"i": i}))
                for i in range(4)]
               + [_reply(SUBMIT_TOOL, "s", 20000, '{"findings": []}')])
    p = _provider(monkeypatch, _scripted(replies, seen), context_tokens=40000,
                  max_tokens=4000)
    run = p.run_agent(system_static="s", system_context="c", user_message="u",
                      tools=_tools(big), max_turns=10)
    assert run.ok
    last = seen[-1]["messages"]
    stubs = [m for m in last if m["role"] == "tool"
             and m["content"].startswith("[Result removed")]
    assert stubs, "expected the oldest results to be stubbed"
    assert last[2]["content"] == "u"
    assert "older tool result(s) were removed" in run.context_note


def test_wrap_up_is_sent_and_further_investigation_is_skipped(monkeypatch):
    seen: list[dict] = []
    calls = {"n": 0}

    def tool(args):
        calls["n"] += 1
        return "r"

    tools = [ToolSpec(name="query_events", description="q",
                      parameters={"type": "object"}, handler=tool),
             _tools()[1]]
    replies = [_reply("query_events", "c1", 8_000),   # window nearly full, nothing to trim
               _reply("query_events", "c2", 8_100),   # model ignores the wrap-up
               _reply(SUBMIT_TOOL, "s", 8_200, '{"findings": []}')]
    p = _provider(monkeypatch, _scripted(replies, seen), context_tokens=11_000,
                  max_tokens=4000)
    run = p.run_agent(system_static="s", system_context="c", user_message="u",
                      tools=tools, max_turns=10)
    assert run.ok
    assert any(m.get("content") == WRAP_UP_MESSAGE for m in seen[1]["messages"])
    assert calls["n"] == 1  # the second query was not run
    assert run.tool_calls[1].detail == "skipped: context window full"
    assert "told to stop investigating" in run.context_note


def test_auto_reads_num_ctx_from_ollama(monkeypatch):
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"parameters": "num_ctx                        30000\n"
                                                           "temperature                    1"})
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=_reply(SUBMIT_TOOL, "1", 50, '{"findings": []}'))

    p = _provider(monkeypatch, handler, context_tokens=-1, base_url="http://test.local/v1")
    assert p.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3).ok
    assert seen[0]["max_tokens"] < 30000


def test_auto_without_num_ctx_leaves_management_off(monkeypatch):
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/show":
            return httpx.Response(404)
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=_reply(SUBMIT_TOOL, "1", 50, '{"findings": []}'))

    p = _provider(monkeypatch, handler, context_tokens=-1)
    assert p.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3).ok
    assert seen[0]["max_tokens"] == 32000


def test_tool_results_are_capped_with_a_hint():
    assert _cap("abc", 10) == "abc"
    out = _cap("a" * 50, 10)
    assert out.startswith("a" * 10 + "\n[Truncated: 50 characters")
    assert "Narrow the query" in out


def test_string_tool_results_are_capped_in_the_loop(monkeypatch):
    seen: list[dict] = []
    replies = [_reply("query_events", "c1", 50),
               _reply(SUBMIT_TOOL, "s", 60, '{"findings": []}')]
    p = _provider(monkeypatch, _scripted(replies, seen), tool_result_max_chars=100)
    assert p.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools("z" * 5000), max_turns=5).ok
    result = next(m for m in seen[1]["messages"] if m["role"] == "tool")
    assert result["content"].startswith("z" * 100 + "\n[Truncated")
