"""Template for a new output destination. Copy, rename, edit.

Pick a renderer by name rather than formatting anything yourself - that is how
every destination inherits a correct report body for free.

Delivery policy is configuration, not code. Users override with
``DAWNPATROL_OUTPUT_<NAME>_RUN_WHEN`` = ALWAYS | NEVER | IMPORTANT | GREEN,AMBER,RED.
"""

from __future__ import annotations

from ..context import RunContext
from ..models import DeliveryResult, Report, Status
from ..secrets import read_env
from .base import Output


class TemplateOutput(Output):
    name = "template"
    renderer = "plaintext"
    requires_env = frozenset({"DAWNPATROL_OUTPUT_TEMPLATE_TARGET"})
    default_run_when = frozenset({Status.GREEN, Status.AMBER, Status.RED})
    default_important_only = False

    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        target = read_env("DAWNPATROL_OUTPUT_TEMPLATE_TARGET", "")
        if not target:
            return DeliveryResult(output=self.name, ok=False, detail="no target configured")
        try:
            # ... deliver `rendered` to `target` ...
            return DeliveryResult(output=self.name, ok=True, detail=f"delivered to {target}")
        except Exception as exc:  # noqa: BLE001 - never raise out of an output
            return DeliveryResult(output=self.name, ok=False, detail=str(exc)[:300])
