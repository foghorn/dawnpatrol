"""The console's only way to DawnPatrol: MCP tool calls.

One short-lived MCP session per call keeps this stateless (no session to
expire or reconnect) at the cost of a handshake per page, which on a LAN is
milliseconds. Tests pass an in-process ``MCPServer`` instead of a URL.
"""

from __future__ import annotations

import json
import time
from typing import Any


class GatewayError(RuntimeError):
    """The MCP server couldn't be reached, or a tool reported an error."""


class McpGateway:
    def __init__(self, url: str = "", token: str = "", *, server: Any = None,
                 timeout: float = 60.0) -> None:
        self.url = url
        self._token = token
        self._server = server
        self._timeout = timeout
        self._tools: tuple[float, set[str]] | None = None

    async def call(self, name: str, **arguments: Any) -> Any:
        """A tool's result: its structured value, or its text (JSON-decoded when
        possible). A tool-level ``{"error": ...}`` result is returned as is, so
        pages can show it; transport failures raise :class:`GatewayError`."""
        from mcp import Client

        args = {k: v for k, v in arguments.items() if v is not None}
        try:
            if self._server is not None:
                async with Client(self._server, cache=None) as client:
                    result = await client.call_tool(name, args)
            else:
                import httpx2
                from mcp.client.streamable_http import streamable_http_client

                headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
                async with httpx2.AsyncClient(headers=headers,
                                              timeout=self._timeout) as http:
                    transport = streamable_http_client(self.url, http_client=http)
                    async with Client(transport, cache=None) as client:
                        result = await client.call_tool(name, args)
        except Exception as exc:  # noqa: BLE001 - shown on the page, never the token
            raise GatewayError(f"MCP call {name} failed: {_describe(exc)}") from exc
        value = _value(result)
        if getattr(result, "is_error", False):
            raise GatewayError(f"MCP tool {name} failed: {_short(str(value))}")
        return value

    async def tool_names(self) -> set[str]:
        """Tools the server offers (cached for a minute): the notebook tools only
        exist when the server has the notebook enabled."""
        if self._tools and time.monotonic() - self._tools[0] < 60:
            return self._tools[1]
        from mcp import Client
        try:
            if self._server is not None:
                async with Client(self._server, cache=None) as client:
                    listed = await client.list_tools()
            else:
                import httpx2
                from mcp.client.streamable_http import streamable_http_client

                headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
                async with httpx2.AsyncClient(headers=headers,
                                              timeout=self._timeout) as http:
                    transport = streamable_http_client(self.url, http_client=http)
                    async with Client(transport, cache=None) as client:
                        listed = await client.list_tools()
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(f"MCP server unreachable: {_describe(exc)}") from exc
        names = {t.name for t in listed.tools}
        self._tools = (time.monotonic(), names)
        return names


def _value(result: Any) -> Any:
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        if set(structured) == {"result"}:
            return structured["result"]
        return structured
    texts = [getattr(c, "text", "") for c in getattr(result, "content", None) or []]
    text = "".join(t for t in texts if t)
    try:
        return json.loads(text)
    except ValueError:
        return text


def _describe(exc: BaseException) -> str:
    """The innermost real error: the MCP client wraps transport failures (a
    refused connection, a 401) in nested exception groups."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    text = str(exc)
    if "401" in text:
        return "the MCP server refused the token (HTTP 401): check DAWNPATROL_WEB_MCP_TOKEN"
    return f"{type(exc).__name__}: {_short(text)}"


def _short(text: str, limit: int = 300) -> str:
    return text if len(text) <= limit else text[:limit] + "..."
