"""Report renderers.

Shared library code rather than plugins, so every output destination inherits a
correct report body instead of re-implementing the formatting contract.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import Report
from . import html, html_email, json_report, markdown, plaintext

RENDERERS: dict[str, Callable[[Report], str]] = {
    "plaintext": plaintext.render,
    "markdown": markdown.render,
    "json": json_report.render,
    "html": html.render,
    "html_email": html_email.render,
}


def render(name: str, report: Report) -> str:
    fn = RENDERERS.get(name)
    if fn is None:
        raise KeyError(f"unknown renderer {name!r}; available: {', '.join(sorted(RENDERERS))}")
    return fn(report)


__all__ = ["render", "RENDERERS", "plaintext", "markdown", "json_report", "html", "html_email"]
