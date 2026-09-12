"""Email delivery over SMTP.

Recipients come from environment variables and are never influenced by report
content. That is deliberate: log data is attacker-influenced, and a pipeline
where retrieved text could redirect an outbound message is a pipeline with an
exfiltration path.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from ..context import RunContext
from ..models import DeliveryResult, Report, Status
from ..render.plaintext import subject_line
from ..secrets import read_bool, read_env, read_int, read_list, read_secret
from .base import Output

log = logging.getLogger(__name__)


class SMTPEmailOutput(Output):
    name = "smtp"
    renderer = "plaintext"
    requires_env = frozenset({"DAWNPATROL_OUTPUT_SMTP_HOST", "DAWNPATROL_OUTPUT_SMTP_TO"})
    default_run_when = frozenset({Status.GREEN, Status.AMBER, Status.RED})
    #: Daily by default - silence is otherwise indistinguishable from a dead agent.
    default_important_only = False

    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        host = read_env("DAWNPATROL_OUTPUT_SMTP_HOST", "")
        recipients = read_list("DAWNPATROL_OUTPUT_SMTP_TO")
        sender = read_env("DAWNPATROL_OUTPUT_SMTP_FROM", "") or f"dawnpatrol@{host}"
        if not host or not recipients:
            return DeliveryResult(output=self.name, ok=False,
                                  detail="SMTP host or recipient list not configured")

        port = read_int("DAWNPATROL_OUTPUT_SMTP_PORT", 587)
        username = read_env("DAWNPATROL_OUTPUT_SMTP_USERNAME", "")
        password = read_secret("DAWNPATROL_OUTPUT_SMTP_PASSWORD")
        use_tls = read_bool("DAWNPATROL_OUTPUT_SMTP_STARTTLS", True)
        use_ssl = read_bool("DAWNPATROL_OUTPUT_SMTP_SSL", False)
        timeout = read_int("DAWNPATROL_OUTPUT_SMTP_TIMEOUT", 30)

        message = EmailMessage()
        message["Subject"] = subject_line(report)
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message["X-DawnPatrol-Status"] = report.status.value
        message["X-DawnPatrol-Run"] = report.run_id
        # Plain text only. No HTML alternative, no attachments: the report must
        # stand alone in the body of the message.
        message.set_content(rendered, subtype="plain", charset="us-ascii")

        if ctx.dry_run:
            return DeliveryResult(output=self.name, ok=True, skipped=True,
                                  detail=f"dry run: would email {len(recipients)} recipient(s)")

        try:
            if use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as server:
                    self._send(server, username, password.get(), message)
            else:
                with smtplib.SMTP(host, port, timeout=timeout) as server:
                    if use_tls:
                        server.starttls(context=ssl.create_default_context())
                    self._send(server, username, password.get(), message)
        except Exception as exc:  # noqa: BLE001 - an output never raises
            return DeliveryResult(output=self.name, ok=False,
                                  detail=f"{type(exc).__name__}: {exc}"[:300])
        return DeliveryResult(output=self.name, ok=True,
                              detail=f"emailed {len(recipients)} recipient(s)")

    @staticmethod
    def _send(server: smtplib.SMTP, username: str, password: str,
              message: EmailMessage) -> None:
        if username:
            server.login(username, password)
        server.send_message(message)
