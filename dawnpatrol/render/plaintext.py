"""Plain-text renderer: 7-bit ASCII, one fact per line.

This module is the entire reason the formatting rules stopped being a prompt
problem. The model never writes the report body, so there is no "do not use
em-dashes" instruction to be forgotten - there is a transliteration table and a
unit test.

One fact per line, ``Label: value``. Not aligned columns: many mail clients
render text/plain in a proportional font, where every space-aligned table
collapses into ragged noise, and you cannot detect that from the sending side.

Content is not hard-wrapped to a fixed column count - that was an early
decision to keep line breaks predictable, but it fought with real mail clients
that already soft-wrap text/plain bodies to the reader's own width, producing
double-wrapped, ragged paragraphs instead. The client decides how to display
long lines now; this renderer's job is ASCII safety and a stable structure,
not column layout.
"""

from __future__ import annotations

import unicodedata

from ..models import Finding, Report, SourceHealth

INDENT = "  "

#: Characters that mojibake through unknown mail gateways, and their ASCII forms.
_TRANSLITERATE = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", " ": " ",
    "→": "->", "←": "<-", "°": " degrees", "•": "*",
    "✓": "[ok]", "✗": "[x]", "×": "x", "±": "+/-",
}


def to_ascii(text: str) -> str:
    """Force 7-bit ASCII. Nothing else survives every mail path reliably."""
    for src, dst in _TRANSLITERATE.items():
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", "replace").decode("ascii")


def format_block(text: str, indent: str = "") -> list[str]:
    """ASCII-safe lines for a block of text, indented, not column-wrapped.

    Paragraph breaks (blank lines in the source) are preserved; each
    paragraph becomes a single line prefixed with ``indent``, however long,
    and the reader's own mail client wraps it for display.
    """
    text = to_ascii(text).strip()
    if not text:
        return []
    out: list[str] = []
    for paragraph in text.split("\n"):
        out.append(f"{indent}{paragraph}" if paragraph.strip() else "")
    return out


def kv(label: str, value: object, indent: str = INDENT) -> str:
    return to_ascii(f"{indent}{label}: {value}")


def heading(number: int, title: str) -> list[str]:
    text = to_ascii(f"{number}. {title.upper()}")
    return ["", text, "=" * len(text)]


def render(report: Report) -> str:
    lines: list[str] = []
    a = lines.append

    title = f"DAWNPATROL REPORT - {report.site_name.upper()}"
    a(to_ascii(title))
    a("=" * len(title))
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
    lines += format_block(summary)

    # 2
    lines += heading(2, "Key statistics")
    lines += _statistics(report)

    # 3
    lines += heading(3, "Findings")
    if not report.findings:
        lines += format_block("No findings this period. Baseline activity only.", INDENT)
    else:
        for finding in report.findings_sorted():
            lines += _finding_block(finding)
    if report.suppressed_findings:
        a("")
        lines += format_block(
            f"{len(report.suppressed_findings)} finding(s) matched an active "
            f"suppression and were withheld:", INDENT
        )
        for f in report.suppressed_findings:
            # Reason on its own line: combining title and reason makes the
            # appendix harder to scan.
            lines += format_block(f"- [{f.severity.label()}] {f.title}", INDENT * 2)
            lines += format_block(f"reason: {f.suppressed_reason}", INDENT * 3)

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
            lines += format_block(f"{note.kind}: {note.text}", INDENT)
    elif report.metric_value("trend.baseline_available") == 0:
        lines += format_block("No prior run. Trend analysis begins once a baseline exists.", INDENT)
    else:
        lines += format_block("No notable trend changes this period.", INDENT)

    # 9
    lines += heading(9, "Recommended actions")
    if report.actions:
        for i, action in enumerate(sorted(report.actions, key=lambda x: x.priority), 1):
            lines += format_block(f"{i}) {action.text}", INDENT)
            if action.command:
                lines += format_block(action.command, INDENT * 2)
    else:
        lines += format_block("No action required. Baseline activity only.", INDENT)

    # 10
    lines += heading(10, "Data quality and caveats")
    lines += _data_quality(report)

    footer = [
        to_ascii(f"DawnPatrol automated report. Run {report.run_id}."),
        "Generated without human review. Do not reply to this message.",
    ]
    sep = "=" * max(len(line) for line in footer)
    a("")
    a(sep)
    a(footer[0])
    a(footer[1])
    a(sep)

    return "\n".join(_enforce(line) for line in lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Section helpers
# --------------------------------------------------------------------------- #


def _enforce(line: str) -> str:
    """Final guarantee: ASCII, no trailing whitespace."""
    return to_ascii(line).rstrip()


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
        for metric in metrics[:24]:
            value = metric.value
            unit = f" {metric.unit}" if metric.unit else ""
            text = f"{value}{unit}"
            delta = metric.delta_pct
            if delta is not None and abs(delta) >= 1:
                text += f"  (prior {_num(metric.prior)}, {delta:+.0f}%)"
            lines.append(kv(metric.display_label(), text, INDENT * 2))
    if not lines:
        lines += format_block("No statistics were produced for this run.", INDENT)
    return lines


def _finding_block(finding: Finding) -> list[str]:
    lines = [""]
    lines += format_block(f"[{finding.severity.label()}] {finding.id} - {finding.title}", INDENT)
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
        lines += format_block(f"{label}: {value}", INDENT * 2)
    if finding.enrichment:
        for ref in finding.enrichment[:3]:
            lines += format_block(f"Reputation: {ref.summary}", INDENT * 2)
    if finding.attribution_caveat:
        lines += format_block(f"Attribution: {finding.attribution_caveat}", INDENT * 2)
    for adjustment in finding.adjustments:
        lines += format_block(f"Adjusted: {adjustment}", INDENT * 2)
    return lines


def _section_body(report: Report, narrative_key: str, metric_sections: list[str]) -> list[str]:
    lines: list[str] = []
    narrative = (report.section_narratives or {}).get(narrative_key)
    if isinstance(narrative, str) and narrative.strip():
        lines += format_block(narrative, INDENT)
        lines.append("")
    shown = 0
    for section in metric_sections:
        metrics = report.metrics_for(section)
        if not metrics:
            continue
        for metric in metrics[:24]:
            unit = f" {metric.unit}" if metric.unit else ""
            lines.append(kv(metric.display_label(), f"{metric.value}{unit}", INDENT))
            shown += 1
    if not lines:
        lines += format_block("No data for this section.", INDENT)
    elif shown == 0:
        lines += format_block("No statistics for this section.", INDENT)
    return lines


def _segment_client_counts(report: Report) -> dict[str, dict[str, int]]:
    """Distinct client population per zone (segment_review.py), straight from
    the traffic itself - not from the curated, necessarily incomplete device
    directory. A NAT-gated segment with no SNMP inventory and no local DNS
    resolver can still show a real count here, because the firewall log's own
    SRC= field carries the client's private address even when the gateway
    masks it heading out to the WAN."""
    counts: dict[str, dict[str, int]] = {}
    for m in report.metrics:
        if m.section != "segments" or not m.key.startswith("zone."):
            continue
        if m.key.endswith(".dns_clients"):
            zone = m.key[len("zone."):-len(".dns_clients")]
            counts.setdefault(zone, {})["dns"] = int(m.value)
        elif m.key.endswith(".fw_clients"):
            zone = m.key[len("zone."):-len(".fw_clients")]
            counts.setdefault(zone, {})["fw"] = int(m.value)
    return counts


def _data_quality(report: Report) -> list[str]:
    lines: list[str] = []
    for health in report.health:
        lines += format_block(
            f"{health.source}: {health.state.value}, {health.records} records over "
            f"{health.span_hours:.2f}h of a {health.requested_hours:.2f}h window",
            INDENT,
        )
        for note in health.notes[:6]:
            lines += format_block(f"- {note}", INDENT * 2)
        if health.probes:
            lines += format_block("probe results:", INDENT * 2)
            for probe in health.probes:
                lines += format_block(
                    f"{probe.name}: {'ok' if probe.ok else 'FAILED'} "
                    f"status={probe.status} records={probe.records}",
                    INDENT * 3,
                )
    segments = _segment_client_counts(report)
    if segments:
        lines += format_block("segment population (distinct clients this run):", INDENT)
        for zone in sorted(segments):
            c = segments[zone]
            bits = []
            if "dns" in c:
                bits.append(f"{c['dns']} via DNS")
            if "fw" in c:
                bits.append(f"{c['fw']} via firewall")
            lines += format_block(f"- {zone}: " + ", ".join(bits), INDENT * 2)
    for canary in report.canaries:
        state = "detected" if canary.detected else "NOT DETECTED"
        lines += format_block(f"canary {canary.name}: {state} - {canary.detail}", INDENT)
    for note in report.data_quality:
        lines += format_block(f"- {note}", INDENT)
    if report.usage.calls:
        lines += format_block(
            f"analysis: {report.usage.calls} model call(s), "
            f"{report.usage.input_tokens} in / {report.usage.output_tokens} out, "
            f"{report.usage.cache_read_tokens} cached, "
            f"est. ${report.usage.cost_usd:.3f}",
            INDENT,
        )
    if not lines:
        lines += format_block("No data quality concerns recorded.", INDENT)
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
