"""Generic webhook delivery: ntfy, Slack, Discord, Home Assistant, anything.

Defaults to important-only, because a chat channel that pings every morning
regardless of content gets muted, and a muted alert channel is worse than none.
"""

from __future__ import annotations

import json
import logging

import httpx

from ..context import RunContext
from ..models import DeliveryResult, Report, Status
from ..render import render as render_with
from ..secrets import read_bool, read_env, read_int, read_secret
from .base import Output

log = logging.getLogger(__name__)


class WebhookOutput(Output):
    name = "webhook"
    renderer = "markdown"
    requires_env = frozenset({"DAWNPATROL_OUTPUT_WEBHOOK_URL"})
    default_run_when = frozenset({Status.GREEN, Status.AMBER, Status.RED})
    default_important_only = True

    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        url = read_env("DAWNPATROL_OUTPUT_WEBHOOK_URL", "")
        if not url:
            return DeliveryResult(output=self.name, ok=False, detail="no URL configured")

        style = (read_env("DAWNPATROL_OUTPUT_WEBHOOK_STYLE", "json") or "json").lower()
        timeout = read_int("DAWNPATROL_OUTPUT_WEBHOOK_TIMEOUT", 30)
        verify = read_bool("DAWNPATROL_OUTPUT_WEBHOOK_VERIFY_TLS", True)

        headers = {"User-Agent": "DawnPatrol"}
        if token := read_secret("DAWNPATROL_OUTPUT_WEBHOOK_TOKEN").get():
            headers["Authorization"] = f"Bearer {token}"

        summary = report.executive_summary or "No analysis narrative produced."
        if style == "text":
            headers["Content-Type"] = "text/plain; charset=utf-8"
            payload = rendered
            kwargs = {"content": payload.encode("utf-8")}
        elif style == "slack":
            headers["Content-Type"] = "application/json"
            kwargs = {"json": {"text": f"*DawnPatrol {report.status.value}* - "
                                       f"{report.finding_count} finding(s)\n{summary}"}}
        else:
            headers["Content-Type"] = "application/json"
            kwargs = {"json": {
                "status": report.status.value,
                "site": report.site_name,
                "run_id": report.run_id,
                "findings": report.finding_count,
                "summary": summary,
                "canaries": report.canary_summary,
                "report_markdown": render_with("markdown", report)[:40000],
                "findings_detail": json.loads(report.to_json())["findings"],
            }}

        if ctx.dry_run:
            return DeliveryResult(output=self.name, ok=True, skipped=True,
                                  detail=f"dry run: would POST to {url.split('?')[0]}")

        try:
            with httpx.Client(timeout=timeout, verify=verify, headers=headers) as client:
                resp = client.post(url, **kwargs)
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return DeliveryResult(output=self.name, ok=False,
                                  detail=f"{type(exc).__name__}: {exc}"[:300])
        return DeliveryResult(output=self.name, ok=True, detail=f"POSTed to {url.split('?')[0]}")
