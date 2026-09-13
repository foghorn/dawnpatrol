"""Bearer-token authentication for the MCP HTTP surface.

The token is either operator-configured (``DAWNPATROL_MCP_TOKEN``, ``_FILE``
variant included) or generated once per process start. A generated token is
logged at startup - that log line is the only place to ever learn it, since it
is never returned by any tool, written to a file, or persisted anywhere.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from typing import Any

from ..config import Settings

log = logging.getLogger(__name__)


def resolve_token(settings: Settings) -> str:
    configured = settings.mcp.token.get()
    if configured:
        settings.secrets.register(configured)
        return configured
    generated = secrets.token_urlsafe(32)
    settings.secrets.register(generated)
    log.warning(
        "DAWNPATROL_MCP_TOKEN is not set; generated a bearer token for this "
        "process only, shown once: %s -- set DAWNPATROL_MCP_TOKEN to keep a "
        "stable token across restarts.", generated,
    )
    return generated


class BearerAuthMiddleware:
    """Wraps an ASGI app, rejecting any HTTP request without the right bearer token."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        supplied = auth[7:] if auth.lower().startswith("bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied, self.token):
            await _deny(send)
            return
        await self.app(scope, receive, send)


async def _deny(send: Any) -> None:
    body = b'{"error":"unauthorized: missing or invalid bearer token"}'
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"www-authenticate", b"Bearer"),
        ],
    })
    await send({"type": "http.response.body", "body": body})
