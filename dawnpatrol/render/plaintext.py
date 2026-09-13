"""Plain-text renderer: 7-bit ASCII, hard-wrapped at 72 columns.

This module is the entire reason the formatting rules stopped being a prompt
problem. The model never writes the report body, so there is no "do not use
em-dashes" instruction to be forgotten - there is a transliteration table and a
unit test.

One fact per line, ``Label: value``. Not aligned columns: many mail clients
render text/plain in a proportional font, where every space-aligned table
collapses into ragged noise, and you cannot detect that from the sending side.
"""

from __future__ import annotations

import textwrap
import unicodedata

from ..models import Finding, Report, SourceHealth

WIDTH = 72
INDENT = "  "

#: Characters that mojibake through unknown mail gateways, and their ASCII forms.
_TRANSLITERATE = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", " ": " ",
    "→": "->", "←": "<-", "°": " degrees", "•": "*",
    "✓": "[ok]", "✗": "[x]", "×": "x", "±": "+/-",
}


def to_ascii(text: str) -> str:
    """Force 7-bit ASCII. Nothing else survives every mail path reliably."""
    for src, dst in _TRANSLITERATE.items():
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", "replace").decode("ascii")


def wrap(text: str, indent: str = "", width: int = WIDTH) -> list[str]:
    text = to_ascii(text).strip()
    if not text:
        return []
    out: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            out.append("")
            continue
        out.extend(textwrap.wrap(
            paragraph, width=width, initial_indent=indent,
            subsequent_indent=indent, break_long_words=True,
            break_on_hyphens=False,
        ) or [indent.rstrip()])
    return out


def kv(label: str, value: object, indent: str = INDENT) -> str:
    return to_ascii(f"{indent}{label}: {value}")[:WIDTH]


def heading(number: int, title: str) -> list[str]:
    text = to_ascii(f"{number}. {title.upper()}")
    return ["", text, "=" * min(len(text), WIDTH)]


def render(report: Report) -> str:
    lines: list[str] = []
    a = lines.append

    title = f"DAWNPATROL REPORT - {report.site_name.upper()}"
    a(to_ascii(title))
    a("=" * min(len(title), WIDTH))
    a("")
    a(kv("Report date", report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"), ""))
    a(kv("Window", f"{report.window.start_str} to {report.window.end_str} UTC", ""))
    a(kv("Coverage", f"{report.window.hours:.2f} hours", ""))
    a(kv("Overall status", report.status.value, ""))
    a(kv("Findings", report.finding_count, ""))
    a(kv("Data sources", _health_summary(report.health), ""))
    if report.canaries:
        a(kv("Detection self-test", report.canary_summary, ""))
    if report.degraded:
        a(kv("NOTE", "AI analysis unavailable - statistics only", ""))

    # 1
    lines += heading(1, "Executive summary")
    summary = report.executive_summary or (
        "No analysis narrative was produced for this run."
    )
    lines += wrap(summary)

    # 2
    lines += heading(2, "Key statistics")
    lines += _statistics(report)

    # 3
    lines += heading(3, "Findings")
    if not report.findings:
        lines += wrap("No findings this period. Baseline activity only.", INDENT)
    else:
        for finding in report.findings_sorted():
            lines += _finding_block(finding)
    if report.suppressed_findings:
        a("")
        lines += wrap(
            f"{len(report.suppressed_findings)} finding(s) matched an active "
            f"suppression and were withheld:", INDENT
        )
        for f in report.suppressed_findings:
            # Reason on its own line: wrapping title and reason together splits
            # the reason across the break and makes the appendix hard to scan.
            lines += wrap(f"- [{f.severity.label()}] {f.title}", INDENT * 2)
            lines += wrap(f"reason: {f.suppressed_reason}", INDENT * 3)

    # 4-7
    lines += heading(4, "Perimeter activity")
    lines += _section_body(report, "perimeter", ["perimeter", "ports"])

    lines += heading(5, "Router and system events")
    lines += _section_body(report, "router", ["router"])

    lines += heading(6, "DNS activity")
    lines += _section_body(report, "dns", ["dns", "dns_blocked", "dns_clients"])

    lines += heading(7, "Segment review")
    lines += _section_body(report, "segments", ["segments"])

    # 8
    lines += heading(8, "Trend watch")
    if report.trend_notes:
        for note in report.trend_notes:
            lines += wrap(f"{note.kind}: {note.text}", INDENT)
    elif report.metric_value("trend.baseline_available") == 0:
        lines += wrap("No prior run. Trend analysis begins once a baseline exists.", INDENT)
    else:
        lines += wrap("No notable trend changes this period.", INDENT)

    # 9
    lines += heading(9, "Recommended actions")
    if report.actions:
        for i, action in enumerate(sorted(report.actions, key=lambda x: x.priority), 1):
            lines += wrap(f"{i}) {action.text}", INDENT)
            if action.command:
                lines += wrap(action.command, INDENT * 2)
    else:
        lines += wrap("No action required. Baseline activity only.", INDENT)

    # 10
    lines += heading(10, "Data quality and caveats")
    lines += _data_quality(report)

    a("")
    a("=" * WIDTH)
    a(to_ascii(f"DawnPatrol automated report. Run {report.run_id}."))
    a("Generated without human review. Do not reply to this message.")
    a("=" * WIDTH)

    return "\n".join(_enforce(line) for line in lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Section helpers
# --------------------------------------------------------------------------- #


def _enforce(line: str) -> str:
    """Final guarantee: ASCII, no trailing whitespace, never over WIDTH."""
    return to_ascii(line).rstrip()[:WIDTH]


def _health_summary(health: list[SourceHealth]) -> str:
    if not health:
        return "none configured"
    return ", ".join(f"{h.source} {h.state.value}" for h in health)


def _statistics(report: Report) -> list[str]:
    lines: list[str] = []
    sections = [
        ("Perimeter", "perimeter"),
        ("DNS", "dns"),
        ("Segments", "segments"),
        ("Router", "router"),
    ]
    for label, key in sections:
        metrics = [m for m in report.metrics_for(key) if not str(m.key).startswith("fw.proto.")]
        if not metrics:
            continue
        lines.append("")
        lines.append(f"{INDENT}{label}:")
        for metric in metrics[:14]:
            value = metric.value
            unit = f" {metric.unit}" if metric.unit else ""
            text = f"{value}{unit}"
            delta = metric.delta_pct
            if delta is not None and abs(delta) >= 1:
                text += f"  (prior {_num(metric.prior)}, {delta:+.0f}%)"
            lines.append(kv(metric.display_label(), text, INDENT * 2))
    if not lines:
        lines += wrap("No statistics were produced for this run.", INDENT)
    return lines


def _finding_block(finding: Finding) -> list[str]:
    lines = [""]
    lines += wrap(f"[{finding.severity.label()}] {finding.id} - {finding.title}", INDENT)
    body = [
        ("Zone", finding.zone),
        ("Confidence", str(finding.confidence)),
        ("What", finding.what),
        ("Why", finding.why),
        ("Not", finding.not_this),
        ("Action", finding.action),
    ]
    for label, value in body:
        if not value:
            continue
        wrapped = wrap(f"{label}: {value}", INDENT * 2)
        lines += wrapped
    if finding.enrichment:
        for ref in finding.enrichment[:3]:
            lines += wrap(f"Reputation: {ref.summary}", INDENT * 2)
    if finding.attribution_caveat:
        lines += wrap(f"Attribution: {finding.attribution_caveat}", INDENT * 2)
    for adjustment in finding.adjustments:
        lines += wrap(f"Adjusted: {adjustment}", INDENT * 2)
    return lines


def _section_body(report: Report, narrative_key: str, metric_sections: list[str]) -> list[str]:
    lines: list[str] = []
    narrative = (report.section_narratives or {}).get(narrative_key)
    if isinstance(narrative, str) and narrative.strip():
        lines += wrap(narrative, INDENT)
        lines.append("")
    shown = 0
    for section in metric_sections:
        metrics = report.metrics_for(section)
        if not metrics:
            continue
        for metric in metrics[:12]:
            unit = f" {metric.unit}" if metric.unit else ""
            lines.append(kv(metric.display_label(), f"{metric.value}{unit}", INDENT))
            shown += 1
    if not lines:
        lines += wrap("No data for this section.", INDENT)
    elif shown == 0:
        lines += wrap("No statistics for this section.", INDENT)
    return lines


def _data_quality(report: Report) -> list[str]:
    lines: list[str] = []
    for health in report.health:
        lines += wrap(
            f"{health.source}: {health.state.value}, {health.records} records over "
            f"{health.span_hours:.2f}h of a {health.requested_hours:.2f}h window",
            INDENT,
        )
        for note in health.notes[:6]:
            lines += wrap(f"- {note}", INDENT * 2)
        if health.probes:
            lines += wrap("probe results:", INDENT * 2)
            for probe in health.probes:
                lines += wrap(
                    f"{probe.name}: {'ok' if probe.ok else 'FAILED'} "
                    f"status={probe.status} records={probe.records}",
                    INDENT * 3,
                )
    for canary in report.canaries:
        state = "detected" if canary.detected else "NOT DETECTED"
        lines += wrap(f"canary {canary.name}: {state} - {canary.detail}", INDENT)
    for note in report.data_quality:
        lines += wrap(f"- {note}", INDENT)
    if report.usage.calls:
        lines += wrap(
            f"analysis: {report.usage.calls} model call(s), "
            f"{report.usage.input_tokens} in / {report.usage.output_tokens} out, "
            f"{report.usage.cache_read_tokens} cached, "
            f"est. ${report.usage.cost_usd:.3f}",
            INDENT,
        )
    if not lines:
        lines += wrap("No data quality concerns recorded.", INDENT)
    return lines


def _num(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.0f}" if float(value).is_integer() else f"{value:.2f}"


def subject_line(report: Report) -> str:
    """Plain ASCII subject. Stable shape so it can be filtered on."""
    return to_ascii(
        f"[DawnPatrol] {report.site_name} - {report.generated_at.strftime('%Y-%m-%d')} "
        f"- {report.status.value} - {report.finding_count} finding(s)"
    )[:150]
