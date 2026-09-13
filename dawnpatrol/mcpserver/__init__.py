"""The optional external-agent surface: read reports and data, trigger a run.

Off by default. Everything here is read-only except one tool
(``trigger_analysis``), and that tool can only ever start the same pipeline a
human running ``dawnpatrol run`` would start - no new capability is created,
only a network-reachable door to existing ones, behind a bearer token.
"""

from .auth import resolve_token
from .server import build_app, serve_forever

__all__ = ["build_app", "resolve_token", "serve_forever"]
