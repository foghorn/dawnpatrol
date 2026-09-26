# Providers

The model that does the actual judgment - stage 7 of the pipeline, the one stage that
costs money - is a plugin like everything else. Swapping `claude-opus-5` for a local
Ollama model, or for `claude-sonnet-5` on a tighter budget, is one environment variable,
never a code change.

Three ship today: `anthropic_provider.py` (the default), `openai_provider.py` (OpenAI's
native `/v1/responses` endpoint), and `openai_compatible.py` (any server speaking
`/v1/chat/completions` with function calling - Ollama, LM Studio, vLLM, LiteLLM,
Open-WebUI, or the hosted OpenAI API itself). See `docs/ARCHITECTURE.md` §6.1 for why
there are two OpenAI-shaped providers rather than one.

Every model you want configured gets its own name and its own env-var namespace -
`DAWNPATROL_AI_<NAME>_PROVIDER` defines the designator, and `DAWNPATROL_AI_ACTIVE=<name>`
picks which one actually runs (`docs/ARCHITECTURE.md` §9). Several fully-configured
designators can be uncommented at once without conflict; a `Provider` subclass never
needs to know its own designator name, since `AISettings` arrives already fully resolved
for whichever one is active.

## The contract

```python
# dawnpatrol/providers/base.py
class Provider(ABC):
    name: str
    requires_env: frozenset[str]
    price_input_per_mtok: float = 0.0
    price_output_per_mtok: float = 0.0
    price_cache_read_per_mtok: float = 0.0

    @abstractmethod
    def run_agent(
        self, *, system_static: str, system_context: str, user_message: str,
        tools: list[ToolSpec], max_turns: int,
        on_turn: Callable[[TokenUsage], None] | None = None,
    ) -> AgentRun:
        """Drive the tool loop until the terminal tool is called or a limit hits."""

    def available(self) -> tuple[bool, str]:
        """Whether this provider can actually run right now (SDK present, key set)."""
        return True, ""
```

`system_static` and `system_context` arrive split deliberately: a provider that supports
prompt caching (Anthropic's does) places its cache breakpoint between them. Both are
byte-stable across runs - no timestamp, run id, or count appears before that boundary,
because that is the classic silent cache-invalidator, and a regression there is
expensive rather than merely wrong.

`AgentRun` is the uniform result every provider returns regardless of backend:
`analysis` (the parsed structured output, or `None` on failure), `usage`, `tool_calls`
(a log of every call made, for the run record), `stop_reason`, `error`.

**Why a terminal tool, not native structured-output.** The harness ends its loop when
the model calls a specific tool (`SUBMIT_TOOL = "submit_analysis"`), rather than relying
on provider-specific JSON-schema response formatting. That keeps every provider on the
identical code path and works even against a local server with no structured-output
support at all - `openai_compatible.py` even falls back to parsing the model's raw
content as JSON if it forgets to call the tool, rather than discarding a complete,
usable analysis over a protocol nicety.

## Walkthrough: `anthropic_provider.py`

Drives a **hand-written loop**, not the SDK's beta tool runner - a deliberate choice: the
harness needs per-turn budget checks and cost accounting mid-loop, plus a clean break on
the terminal tool, and keeping the loop's shape identical to `openai_compatible.py`'s
makes both easy to reason about side by side. Two things worth knowing if you're
building a third provider:

- **The cache breakpoint is a `cache_control` block on the second system-prompt
  segment** (`system_context`), not the first. Everything before it - tool definitions,
  the static system prompt - is sent every turn; everything from the breakpoint onward
  is what actually gets cached.
- **A refusal is a distinct `stop_reason`, not an exception.** `run.error` gets set to a
  human-readable reason and the run ends cleanly; a beta refusal-fallback parameter
  (`betas: [...]`, `fallbacks: "default"`) degrades to another model rather than
  producing no report at all, and the provider retries once on the plain path if the
  server rejects the beta parameters outright (`_BetaUnsupported`).

## Walkthrough: `openai_compatible.py`

Plain `httpx`, not the `openai` package - local servers vary in small, annoying ways
(a missing field here, a slightly different error shape there), and a thin client
tolerates that better than a strict SDK would. Pricing is **zero by default**
(that designator's own `_PRICE_IN`/`_PRICE_OUT`), since most self-hosted models are free
to run; set both if you're pointing at a paid hosted endpoint through this same interface
and want real cost accounting. `openai_provider.py` follows the identical pattern for
`/v1/responses` - see its module docstring for the two things it does differently
(`reasoning.effort`, `store: false`) and why.

## Build your own

Copy an existing provider rather than starting from a blank file - the loop shape (turn
counter, tool dispatch, terminal-tool break, usage accounting via `on_turn`) is the part
worth reusing, and it's nearly identical across the three that ship. The parts that
actually differ are the wire format (Anthropic's content-block messages, OpenAI's
`tool_calls` array, `/v1/responses`' flat `input` items) and how you detect a cache hit in
the usage payload.

```python
class MyBackendProvider(Provider):
    name = "my_backend"
    requires_env = frozenset()

    def run_agent(self, *, system_static, system_context, user_message,
                 tools, max_turns, on_turn=None) -> AgentRun:
        run = AgentRun()
        by_name = {t.name: t for t in tools}
        # ... build the request, loop on tool calls, dispatch through by_name,
        #     break on the terminal tool (spec.terminal) ...
        return run
```

`build_provider(settings)` (`providers/registry.py`) discovers your class the same way
every other plugin folder does (module import + subclass collection), but selects it
purely by matching `settings.provider` against `name` - unlike sources/analyzers/
enrichers/outputs, a provider's `requires_env` isn't checked for selection; `available()`
is what actually reports whether it can run (SDK installed, key present). Your provider
becomes usable the moment some designator sets `DAWNPATROL_AI_<NAME>_PROVIDER=my_backend`.

### Wire it up and test it

```bash
# .env: DAWNPATROL_AI_TEST_PROVIDER=my_backend, DAWNPATROL_AI_TEST_MODEL=...,
#       DAWNPATROL_AI_ACTIVE=test (or leave ACTIVE unset if it's the only one defined)
dawnpatrol validate
# reports "ready" or the specific reason available() says it isn't, for every
# configured designator - not just the active one
dawnpatrol run --dry-run   # exercises the real loop against your real backend, no delivery
```

For an offline test, follow `tests/test_pipeline.py`'s `StubProvider` pattern: a
`Provider` subclass that returns a canned `AgentRun` and records what tools it was
offered, so the full pipeline - including adjudication against your provider's exact
output shape - runs in CI with zero API spend.
