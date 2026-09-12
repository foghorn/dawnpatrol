"""JSON renderer: the machine-readable form of a report."""

from __future__ import annotations

from ..models import Report


def render(report: Report) -> str:
    return report.to_json()
