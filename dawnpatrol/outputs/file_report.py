"""Write the report to disk. Always enabled; the durable record of every run."""

from __future__ import annotations

import logging
from pathlib import Path

from ..context import RunContext
from ..models import DeliveryResult, Report, Status
from ..render import render as render_with
from ..secrets import read_env, read_list
from .base import Output

log = logging.getLogger(__name__)


class FileReportOutput(Output):
    name = "file"
    renderer = "plaintext"
    requires_env = frozenset()   # always available; needs no configuration
    default_run_when = frozenset({Status.GREEN, Status.AMBER, Status.RED})

    @property
    def formats(self) -> list[str]:
        return read_list("DAWNPATROL_OUTPUT_FILE_FORMATS", ["plaintext", "json"])

    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        base = Path(read_env("DAWNPATROL_OUTPUT_DIR", "./out") or "./out")
        day = report.generated_at.strftime("%Y-%m-%d")
        target = base / day
        written: list[str] = []
        try:
            target.mkdir(parents=True, exist_ok=True)
            for fmt in self.formats:
                suffix = {"plaintext": "txt", "markdown": "md", "json": "json",
                         "html": "html"}.get(fmt, fmt)
                body = rendered if fmt == self.renderer else render_with(fmt, report)
                path = target / f"report-{report.run_id}.{suffix}"
                path.write_text(body, encoding="utf-8")
                written.append(str(path))

                # `latest.*` is what a dashboard or scp job watches.
                latest = base / f"latest.{suffix}"
                latest.write_text(body, encoding="utf-8")
        except OSError as exc:
            return DeliveryResult(output=self.name, ok=False, detail=f"write failed: {exc}")
        except KeyError as exc:
            return DeliveryResult(output=self.name, ok=False, detail=f"bad format: {exc}")
        return DeliveryResult(output=self.name, ok=True,
                              detail=f"wrote {len(written)} file(s) to {target}")
