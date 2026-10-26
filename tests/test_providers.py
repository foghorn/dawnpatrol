"""OpenAICompatibleProvider: payload construction and the two deployment-specific
knobs (DAWNPATROL_AI_MAX_TOKENS_PARAM, DAWNPATROL_AI_REASONING_EFFORT) added
after gpt-5.6-sol (a real OpenAI reasoning-tier model, verified live) turned
out to reject both the endpoint's classic max_tokens parameter and tool
calling without an explicit reasoning_effort override.
"""

from __future__ import annotations

import json

import httpx
import pytest

from dawnpatrol.config import AISettings
from dawnpatrol.providers.base import SUBMIT_TOOL, SubmissionRejected, ToolSpec
from dawnpatrol.providers.openai_compatible import OpenAICompatibleProvider
from dawnpatrol.providers.openai_provider import OpenAIProvider
from dawnpatrol.secrets import SecretStr


def _settings(**overrides) -> AISettings:
    base = AISettings(provider="openai_compatible", base_url="http://test.local",
                      model="test-model", max_tokens=1234)
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


_RealClient = httpx.Client


def _provider(monkeypatch, settings, handler) -> OpenAICompatibleProvider:
    monkeypatch.setattr(
        "dawnpatrol.providers.openai_compatible.httpx.Client",
        lambda **kw: _RealClient(transport=httpx.MockTransport(handler)),
    )
    return OpenAICompatibleProvider(settings)


def _tools() -> list[ToolSpec]:
    return [
        ToolSpec(name="describe_schema", description="d", parameters={"type": "object"},
                 handler=lambda args: "schema info"),
        ToolSpec(name=SUBMIT_TOOL, description="submit", parameters={"type": "object"},
                 handler=lambda args: None, terminal=True),  # None accepts
    ]


def _completion(**message) -> dict:
    return {
        "choices": [{"finish_reason": message.pop("finish_reason", "stop"), "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def test_default_payload_uses_max_tokens(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_completion(
            content=None, tool_calls=[{"id": "1", "type": "function",
                                       "function": {"name": SUBMIT_TOOL, "arguments": "{}"}}],
            finish_reason="tool_calls",
        ))

    provider = _provider(monkeypatch, _settings(), handler)
    provider.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3)
    assert captured["body"]["max_tokens"] == 1234
    assert "max_completion_tokens" not in captured["body"]
    assert "reasoning_effort" not in captured["body"]


def test_max_tokens_param_override_sends_max_completion_tokens(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_completion(
            content=None, tool_calls=[{"id": "1", "type": "function",
                                       "function": {"name": SUBMIT_TOOL, "arguments": "{}"}}],
            finish_reason="tool_calls",
        ))

    settings = _settings(max_tokens_param="max_completion_tokens")
    provider = _provider(monkeypatch, settings, handler)
    provider.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3)
    assert captured["body"]["max_completion_tokens"] == 1234
    assert "max_tokens" not in captured["body"]


def test_reasoning_effort_included_only_when_set(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_completion(
            content=None, tool_calls=[{"id": "1", "type": "function",
                                       "function": {"name": SUBMIT_TOOL, "arguments": "{}"}}],
            finish_reason="tool_calls",
        ))

    settings = _settings(reasoning_effort="none")
    provider = _provider(monkeypatch, settings, handler)
    provider.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3)
    assert captured["body"]["reasoning_effort"] == "none"


def test_tool_call_then_submit_round_trip(monkeypatch):
    """A gpt-5.6-sol-shaped exchange: one investigative tool call, then submit -
    still works end to end with the new payload fields in play."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_completion(
                content=None,
                tool_calls=[{"id": "1", "type": "function",
                            "function": {"name": "describe_schema", "arguments": "{}"}}],
                finish_reason="tool_calls",
            ))
        return httpx.Response(200, json=_completion(
            content=None,
            tool_calls=[{"id": "2", "type": "function",
                        "function": {"name": SUBMIT_TOOL,
                                    "arguments": '{"findings": [], "executive_summary": "ok"}'}}],
            finish_reason="tool_calls",
        ))

    monkeypatch.setenv("DAWNPATROL_AI_REASONING_EFFORT", "none")
    provider = _provider(monkeypatch, _settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=5)
    assert run.error is None
    assert run.analysis == {"findings": [], "executive_summary": "ok"}
    assert calls["n"] == 2


def test_unsupported_max_tokens_error_surfaces_clearly(monkeypatch):
    """The real error text gpt-5.6-sol returns for the wrong param name - the
    provider must surface it, not swallow it as a generic failure."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={
            "error": {"message": "Unsupported parameter: 'max_tokens' is not "
                                 "supported with this model. Use 'max_completion_tokens' "
                                 "instead.", "code": "unsupported_parameter"},
        })

    provider = _provider(monkeypatch, _settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)
    assert run.error is not None
    assert "max_completion_tokens" in run.error


def test_openai_compatible_cost_does_not_double_count_cached_tokens(monkeypatch):
    """Same fix, same reasoning, as openai_provider.py's equivalent test -
    this provider's /v1/chat/completions usage shape has the identical
    inclusive-input_tokens convention whenever the backend is OpenAI itself
    or a faithful proxy (LiteLLM, for one)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "tool_calls", "message": {
                "content": None,
                "tool_calls": [{"id": "1", "type": "function",
                               "function": {"name": SUBMIT_TOOL, "arguments": "{}"}}],
            }}],
            "usage": {
                "prompt_tokens": 3014, "completion_tokens": 7,
                "prompt_tokens_details": {"cached_tokens": 3004, "cache_write_tokens": 7},
            },
        })

    provider = _provider(monkeypatch, _settings(), handler)
    provider.price_input_per_mtok = 4.00
    provider.price_output_per_mtok = 20.00
    provider.price_cache_read_per_mtok = 0.40
    provider.price_cache_write_per_mtok = 5.00

    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)

    fresh_input = 3014 - 3004
    expected = (fresh_input / 1_000_000 * 4.00 + 3004 / 1_000_000 * 0.40
               + 7 / 1_000_000 * 20.00 + 7 / 1_000_000 * 5.00)
    assert run.usage.cost_usd == pytest.approx(expected)


# --------------------------------------------------------------------------- #
# OpenAIProvider: /v1/responses, verified live against gpt-5.6-sol before
# this file existed - tool calling and reasoning work together natively
# there (unlike openai_compatible's /v1/chat/completions), and temperature
# is rejected outright for reasoning models.
# --------------------------------------------------------------------------- #


def _oa_settings(**overrides) -> AISettings:
    base = AISettings(provider="openai", model="gpt-5.6-sol", max_tokens=1234,
                      effort="high", api_key=SecretStr("sk-test"))
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _oa_provider(monkeypatch, settings, handler) -> OpenAIProvider:
    monkeypatch.setattr(
        "dawnpatrol.providers.openai_provider.httpx.Client",
        lambda **kw: _RealClient(transport=httpx.MockTransport(handler)),
    )
    return OpenAIProvider(settings)


def _oa_function_call(name: str, arguments: str, call_id: str = "call_1") -> dict:
    return {"type": "function_call", "status": "completed", "call_id": call_id,
            "name": name, "arguments": arguments}


def _oa_response(output: list[dict], status: str = "completed", *,
                 input_tokens: int = 100, output_tokens: int = 20,
                 cached_tokens: int = 30, cache_write_tokens: int = 0) -> dict:
    return {
        "status": status,
        "output": output,
        "usage": {
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "input_tokens_details": {"cached_tokens": cached_tokens,
                                     "cache_write_tokens": cache_write_tokens},
            "output_tokens_details": {"reasoning_tokens": 5},
        },
    }


def test_openai_provider_unavailable_without_api_key():
    settings = _oa_settings(api_key=SecretStr(""))
    ok, reason = OpenAIProvider(settings).available()
    assert ok is False
    assert "API key" in reason


def test_openai_provider_available_with_api_key():
    ok, _reason = OpenAIProvider(_oa_settings()).available()
    assert ok is True


def test_openai_provider_payload_omits_temperature_and_sets_store_false(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL, "{}")],
        ))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    provider.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=3)
    assert captured["body"]["store"] is False
    assert captured["body"]["reasoning"] == {"effort": "high"}
    assert "temperature" not in captured["body"]
    assert captured["body"]["max_output_tokens"] == 1234


def test_openai_provider_endpoint_defaults_to_the_real_api(monkeypatch):
    provider = _oa_provider(monkeypatch, _oa_settings(), lambda r: httpx.Response(200, json={}))
    assert provider.endpoint == "https://api.openai.com/v1/responses"


def test_openai_provider_tool_call_then_submit_round_trip(monkeypatch):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        body = json.loads(request.content)
        if calls["n"] == 1:
            return httpx.Response(200, json=_oa_response(
                [_oa_function_call("describe_schema", "{}", call_id="call_a")],
            ))
        # The prior function_call and its output must both be present.
        types = [item.get("type") for item in body["input"]]
        assert "function_call" in types
        assert "function_call_output" in types
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL,
                               '{"findings": [], "executive_summary": "ok"}',
                               call_id="call_b")],
        ))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=5)
    assert run.error is None
    assert run.analysis == {"findings": [], "executive_summary": "ok"}
    assert calls["n"] == 2


def test_openai_provider_drops_reasoning_items_from_input_history(monkeypatch):
    captured_second_call = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if not captured_second_call:
            captured_second_call["first_input_len"] = len(body["input"])
            return httpx.Response(200, json=_oa_response([
                {"type": "reasoning", "content": [], "encrypted_content": "abc"},
                _oa_function_call("describe_schema", "{}", call_id="call_a"),
            ]))
        captured_second_call["types"] = [item.get("type") for item in body["input"]]
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL, "{}", call_id="call_b")],
        ))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    provider.run_agent(system_static="s", system_context="c", user_message="u",
                       tools=_tools(), max_turns=5)
    assert "reasoning" not in captured_second_call["types"]


def test_openai_provider_message_only_output_falls_back_to_content_json(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_oa_response([
            {"type": "message", "status": "completed", "role": "assistant",
             "content": [{"type": "output_text",
                         "text": '{"findings": [], "executive_summary": "no tool call"}'}]},
        ]))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)
    assert run.error is None
    assert run.analysis == {"findings": [], "executive_summary": "no tool call"}
    assert run.transcript_note is not None


def test_openai_provider_surfaces_the_real_api_error_message(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "error": {"message": "Unsupported parameter: 'temperature' is not "
                                 "supported with this model."},
        })

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)
    assert run.error is not None
    assert "temperature" in run.error


def test_openai_provider_usage_maps_cached_tokens(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL, "{}")],
        ))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)
    assert run.usage.input_tokens == 100
    assert run.usage.output_tokens == 20
    assert run.usage.cache_read_tokens == 30
    assert run.usage.calls == 1


def test_openai_provider_cost_does_not_double_count_cached_tokens(monkeypatch):
    """input_tokens=3014, cached_tokens=3004, cache_write_tokens=7,
    output_tokens=7 - a real usage object from resending an identical
    ~3010-token prefix against gpt-5.6-sol (see openai_provider.py's
    estimate_cost docstring). Real rates: $4.00/$20.00/$0.40/$5.00 per Mtok
    for input/output/cache-read/cache-write. The naive (Anthropic-style)
    formula would bill the 3004 cached tokens twice - once at $4.00 as part
    of input_tokens, again at $0.40 - overstating cost by roughly 75x on
    just that component."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL, "{}")],
            input_tokens=3014, output_tokens=7, cached_tokens=3004, cache_write_tokens=7,
        ))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    provider.price_input_per_mtok = 4.00
    provider.price_output_per_mtok = 20.00
    provider.price_cache_read_per_mtok = 0.40
    provider.price_cache_write_per_mtok = 5.00

    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_tools(), max_turns=3)

    fresh_input = 3014 - 3004
    expected = (fresh_input / 1_000_000 * 4.00 + 3004 / 1_000_000 * 0.40
               + 7 / 1_000_000 * 20.00 + 7 / 1_000_000 * 5.00)
    assert run.usage.cost_usd == pytest.approx(expected)
    assert run.usage.cost_usd == pytest.approx(0.0014166, abs=1e-7)

    naive_double_counted = (3014 / 1_000_000 * 4.00 + 3004 / 1_000_000 * 0.40
                            + 7 / 1_000_000 * 20.00 + 7 / 1_000_000 * 5.00)
    assert run.usage.cost_usd < naive_double_counted


# --------------------------------------------------------------------------- #
# Submission format check
# --------------------------------------------------------------------------- #


def _checking_tools(verdicts: list) -> list[ToolSpec]:
    """A submit tool whose check returns each verdict in turn: None accepts,
    text asks for a correction, an exception rejects for good."""
    def check(args):
        verdict = verdicts.pop(0)
        if isinstance(verdict, Exception):
            raise verdict
        return verdict

    return [_tools()[0], ToolSpec(name=SUBMIT_TOOL, description="submit",
                                  parameters={"type": "object"}, handler=check,
                                  terminal=True)]


def _submit_completion(call_id: str, arguments: dict) -> dict:
    return _completion(content=None, finish_reason="tool_calls", tool_calls=[
        {"id": call_id, "type": "function",
         "function": {"name": SUBMIT_TOOL, "arguments": json.dumps(arguments)}}])


def test_a_correction_goes_back_as_the_tool_result_and_the_retry_is_accepted(monkeypatch):
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=_submit_completion(
            str(len(bodies)), {"attempt": len(bodies)}))

    provider = _provider(monkeypatch, _settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_checking_tools(["use objects", None]), max_turns=5)
    assert run.error is None
    assert run.analysis == {"attempt": 2}
    assert bodies[1]["messages"][-1] == {"role": "tool", "tool_call_id": "1",
                                         "name": SUBMIT_TOOL, "content": "use objects"}


def test_a_rejected_submission_ends_the_run_with_its_reason(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_submit_completion("1", {"findings": "bad"}))

    provider = _provider(monkeypatch, _settings(), handler)
    run = provider.run_agent(
        system_static="s", system_context="c", user_message="u", max_turns=5,
        tools=_checking_tools(["fix it", SubmissionRejected("still wrong")]))
    assert run.analysis is None
    assert run.error == "still wrong"


def test_an_analysis_returned_as_content_is_checked_too(monkeypatch):
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(200, json=_completion(
                content=json.dumps({"findings": ["not an object"]})))
        return httpx.Response(200, json=_submit_completion("2", {"findings": []}))

    provider = _provider(monkeypatch, _settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_checking_tools(["use objects", None]), max_turns=5)
    assert run.analysis == {"findings": []}
    assert bodies[1]["messages"][-1] == {"role": "user", "content": "use objects"}


def test_openai_provider_sends_a_correction_as_the_call_output(monkeypatch):
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        n = len(bodies)
        return httpx.Response(200, json=_oa_response(
            [_oa_function_call(SUBMIT_TOOL, json.dumps({"attempt": n}), call_id=f"c{n}")]))

    provider = _oa_provider(monkeypatch, _oa_settings(), handler)
    run = provider.run_agent(system_static="s", system_context="c", user_message="u",
                             tools=_checking_tools(["use objects", None]), max_turns=5)
    assert run.analysis == {"attempt": 2}
    assert bodies[1]["input"][-1] == {"type": "function_call_output", "call_id": "c1",
                                      "output": "use objects"}
