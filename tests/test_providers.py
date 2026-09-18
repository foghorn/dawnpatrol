"""OpenAICompatibleProvider: payload construction and the two deployment-specific
knobs (DAWNPATROL_AI_MAX_TOKENS_PARAM, DAWNPATROL_AI_REASONING_EFFORT) added
after gpt-5.6-sol (a real OpenAI reasoning-tier model, verified live) turned
out to reject both the endpoint's classic max_tokens parameter and tool
calling without an explicit reasoning_effort override.
"""

from __future__ import annotations

import json

import httpx

from dawnpatrol.config import AISettings
from dawnpatrol.providers.base import SUBMIT_TOOL, ToolSpec
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
                 handler=lambda args: args, terminal=True),
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

    monkeypatch.setenv("DAWNPATROL_AI_MAX_TOKENS_PARAM", "max_completion_tokens")
    provider = _provider(monkeypatch, _settings(), handler)
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

    monkeypatch.setenv("DAWNPATROL_AI_REASONING_EFFORT", "none")
    provider = _provider(monkeypatch, _settings(), handler)
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


def _oa_response(output: list[dict], status: str = "completed") -> dict:
    return {
        "status": status,
        "output": output,
        "usage": {
            "input_tokens": 100, "output_tokens": 20,
            "input_tokens_details": {"cached_tokens": 30, "cache_write_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 5},
        },
    }


def test_openai_provider_unavailable_without_api_key():
    settings = _oa_settings(api_key=SecretStr(""))
    ok, reason = OpenAIProvider(settings).available()
    assert ok is False
    assert "DAWNPATROL_AI_API_KEY" in reason


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
