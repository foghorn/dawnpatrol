"""Template for a new model provider. Copy, rename, edit.

A provider owns its request shape and its own tool loop. The contract is only:
take a system prompt and a tool surface, loop until the terminal tool fires or
``max_turns`` is reached, and return an AgentRun.

Use the terminal-tool pattern (a ``submit_analysis`` tool) rather than
provider-specific structured output - it works identically on hosted APIs and
local servers with no JSON-schema support.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import TokenUsage
from .base import SUBMIT_TOOL, AgentRun, Provider, ToolSpec


class TemplateProvider(Provider):
    #: requires_env isn't checked for provider selection (build_provider matches
    #: `settings.provider` against `name` only) - leave it empty. This provider
    #: becomes usable the moment some designator sets
    #: DAWNPATROL_AI_<NAME>_PROVIDER=template; settings.api_key/model/base_url/
    #: etc. arrive already resolved for whichever designator is active.
    name = "template"
    requires_env = frozenset()
    price_input_per_mtok = 0.0
    price_output_per_mtok = 0.0

    def available(self) -> tuple[bool, str]:
        if not self.settings.api_key:
            return False, "no API key set for the active AI config"
        return True, ""

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
        _by_name = {t.name: t for t in tools}
        # ... build the request, loop on tool calls, dispatch through by_name ...
        # When the model calls SUBMIT_TOOL, set run.analysis and break.
        run.error = f"{self.name} provider is a template and does not implement {SUBMIT_TOOL}"
        return run
