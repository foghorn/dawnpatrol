"""Optional web console: latest run and report, findings with their evidence,
starting and watching runs, and the notebook - all through the MCP server.

Built into ``dawnpatrol serve`` with ``DAWNPATROL_WEB_ENABLED=true`` (next to
the MCP server), or on its own with ``dawnpatrol web``. See
docs/web-console.md.
"""

from __future__ import annotations

import ipaddress
import logging

from ..config import Settings

log = logging.getLogger(__name__)


def mcp_url(settings: Settings) -> str:
    if settings.web.mcp_url:
        return settings.web.mcp_url
    return f"http://127.0.0.1:{settings.mcp.port}{settings.mcp.path}"


def serve_forever(settings: Settings, default_token: str = "") -> None:
    """Blocking: run the console (call from its own thread when built in)."""
    try:
        import uvicorn

        from .app import build_app
        from .gateway import McpGateway
    except ImportError as exc:
        log.error("web console unavailable: %s (install dawnpatrol[web])", exc)
        return

    web = settings.web
    token = web.mcp_token.get() or settings.mcp.token.get() or default_token
    if not token:
        log.warning("web console: no MCP token (DAWNPATROL_WEB_MCP_TOKEN or "
                    "DAWNPATROL_MCP_TOKEN); calls will be refused by a protected server")
    password = web.password.get()
    if not password and not _loopback(web.host):
        log.warning("web console: no password set (DAWNPATROL_WEB_PASSWORD) - anyone "
                    "who can reach %s:%d can read reports and start runs",
                    web.host, web.port)
    app = build_app(McpGateway(mcp_url(settings), token), password=password,
                    session_hours=web.session_hours)
    log.info("web console listening on http://%s:%d (MCP at %s, %s)", web.host, web.port,
             mcp_url(settings), "password required" if password else "no password")
    uvicorn.Server(uvicorn.Config(app, host=web.host, port=web.port,
                                  log_level="warning")).run()


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"
