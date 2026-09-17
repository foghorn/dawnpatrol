"""HTML email renderer: a formatted report for the inbox, not the browser.

Deliberately a separate module from ``render/html.py`` (a full page with a
``<style>`` block, meant for a browser, a webhook, or an archived file copy)
rather than a shared one, because email has a different rendering contract:
mail clients cannot be trusted to honour a ``<style>`` block or external CSS
at all. Outlook's desktop client renders HTML through Word's engine, not a
browser engine, and strips or mis-applies a large share of ordinary CSS;
webmail clients vary in what they leave in a stripped ``<head>``. The one
technique that reaches every client the same way is inlining every style
directly on the element it applies to, using only the narrow set of
properties (font, color, background, padding, border, border-radius) that
survive that translation consistently. No ``<style>`` block, no external
assets, no JavaScript.

Same report, same fields, same section ordering as ``render/html.py`` and
``render/plaintext.py`` - only the markup differs.
"""

from __future__ import annotations

from html import escape

from ..models import Finding, Report

#: (background, text) per status, used for the header badge.
_BADGE_COLORS = {
    "GREEN": ("#dafbe1", "#116329"),
    "AMBER": ("#fff8c5", "#7d4e00"),
    "RED": ("#ffebe9", "#82071e"),
}
#: Left-border color per severity, used on each finding card.
_SEVERITY_COLORS = {
    "CRITICAL": "#cf222e", "HIGH": "#cf222e",
    "MEDIUM": "#9a6700",
    "LOW": "#57606a", "INFO": "#57606a",
}

_FONT = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif"
_TEXT = "#1b1f23"
_MUTED = "#57606a"
_BORDER = "#d0d7de"

_BODY_STYLE = (
    f"margin:0;padding:24px 12px;background:#f6f8fa;"
    f"font-family:{_FONT};color:{_TEXT};"
)
_CARD_STYLE = (
    "max-width:680px;margin:0 auto;background:#ffffff;"
    f"border:1px solid {_BORDER};border-radius:10px;"
    "padding:28px 32px;"
)
_H1_STYLE = "margin:0 0 6px 0;font-size:21px;font-weight:600;"
_META_STYLE = f"margin:0 0 4px 0;font-size:13px;color:{_MUTED};line-height:1.6;"
_H2_STYLE = (
    f"margin:28px 0 10px 0;font-size:13px;font-weight:700;color:{_MUTED};"
    f"text-transform:uppercase;letter-spacing:.05em;"
    f"border-bottom:1px solid {_BORDER};padding-bottom:6px;"
)
_P_STYLE = "margin:0 0 12px 0;font-size:14px;line-height:1.6;"
_BADGE_STYLE = (
    "display:inline-block;padding:3px 11px;border-radius:12px;"
    "font-weight:700;font-size:12px;letter-spacing:.02em;"
)
_UL_STYLE = "margin:0 0 12px 0;padding-left:20px;font-size:14px;line-height:1.6;"
_LI_STYLE = "margin-bottom:6px;"
_FINDING_STYLE = (
    "margin:0 0 16px 0;padding:2px 0 2px 16px;"
    "border-left-width:4px;border-left-style:solid;"
)
_FINDING_TITLE_STYLE = "margin:0 0 6px 0;font-size:15px;font-weight:600;"
_DT_STYLE = f"font-weight:700;color:{_MUTED};font-size:12px;margin-top:6px;"
_DD_STYLE = "margin:1px 0 0 0;font-size:14px;line-height:1.55;"
_TABLE_STYLE = "border-collapse:collapse;width:100%;font-size:13px;margin:0 0 12px 0;"
_TH_STYLE = (
    f"text-align:left;padding:6px 10px;border-bottom:1px solid {_BORDER};"
    f"color:{_MUTED};font-weight:600;"
)
_TD_STYLE = "padding:6px 10px;border-bottom:1px solid #eaeef2;"
_FOOTER_STYLE = (
    f"margin-top:28px;padding-top:14px;border-top:1px solid {_BORDER};"
    f"color:{_MUTED};font-size:12px;line-height:1.6;"
)


def render(report: Report) -> str:
    a: list[str] = []
    add = a.append
    bg, fg = _BADGE_COLORS.get(report.status.value, ("#eaeef2", _MUTED))

    add('<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1"></head>')
    add(f'<body style="{_BODY_STYLE}"><div style="{_CARD_STYLE}">')

    add(f'<h1 style="{_H1_STYLE}">DawnPatrol - {escape(report.site_name)}</h1>')
    add(f'<p style="{_META_STYLE}">'
        f'<span style="{_BADGE_STYLE}background:{bg};color:{fg};">'
        f'{escape(report.status.value)}</span>'
        f'&nbsp;&nbsp;Window {escape(report.window.start_str)} to '
        f'{escape(report.window.end_str)} UTC ({report.window.hours:.2f}h)</p>')
    add(f'<p style="{_META_STYLE}">{report.finding_count} finding(s) &middot; '
        f'sources: {escape(_health_summary(report))}')
    if report.canaries:
        add(f' &middot; self-test: {escape(report.canary_summary)}')
    add('</p>')
    if report.degraded:
        add(f'<p style="{_P_STYLE}"><em>AI analysis was unavailable for this run. '
            f'Statistics only.</em></p>')

    add(f'<h2 style="{_H2_STYLE}">Executive summary</h2>')
    summary = escape(report.executive_summary) or "<em>No analysis narrative produced.</em>"
    add(f'<p style="{_P_STYLE}">{summary}</p>')

    add(f'<h2 style="{_H2_STYLE}">Findings</h2>')
    if not report.findings:
        add(f'<p style="{_P_STYLE}">No findings this period. Baseline activity only.</p>')
    else:
        for f in report.findings_sorted():
            add(_finding_html(f))
    if report.suppressed_findings:
        add(f'<p style="{_P_STYLE}">{len(report.suppressed_findings)} finding(s) matched '
            f'an active suppression and were withheld:</p>')
        add(f'<ul style="{_UL_STYLE}">')
        for f in report.suppressed_findings:
            add(f'<li style="{_LI_STYLE}">[{escape(f.severity.label())}] '
                f'{escape(f.title)} &mdash; <em>{escape(f.suppressed_reason)}</em></li>')
        add('</ul>')

    add(f'<h2 style="{_H2_STYLE}">Key statistics</h2>')
    add(_statistics_table(report))

    if report.trend_notes:
        add(f'<h2 style="{_H2_STYLE}">Trends</h2><ul style="{_UL_STYLE}">')
        for t in report.trend_notes:
            add(f'<li style="{_LI_STYLE}"><strong>{escape(t.kind)}:</strong> '
                f'{escape(t.text)}</li>')
        add('</ul>')

    if report.actions:
        add(f'<h2 style="{_H2_STYLE}">Recommended actions</h2><ol style="{_UL_STYLE}">')
        for action in sorted(report.actions, key=lambda x: x.priority):
            add(f'<li style="{_LI_STYLE}">{escape(action.text)}')
            if action.command:
                add(f'<pre style="background:#f6f8fa;border:1px solid {_BORDER};'
                    f'border-radius:4px;padding:8px 10px;font-size:12px;'
                    f'overflow-x:auto;margin:6px 0 0 0;">{escape(action.command)}</pre>')
            add('</li>')
        add('</ol>')

    add(f'<h2 style="{_H2_STYLE}">Data quality</h2><ul style="{_UL_STYLE}">')
    for h in report.health:
        add(f'<li style="{_LI_STYLE}"><strong>{escape(h.source)}</strong> &mdash; '
            f'{escape(h.state.value)}, {h.records} records over {h.span_hours:.2f}h '
            f'(requested {h.requested_hours:.2f}h)')
        if h.notes:
            add(f'<ul style="{_UL_STYLE}">' +
                "".join(f'<li style="{_LI_STYLE}">{escape(n)}</li>' for n in h.notes[:5]) +
                '</ul>')
        add('</li>')
    segments = _segment_client_counts(report)
    if segments:
        add(f'<li style="{_LI_STYLE}"><strong>segment population</strong> '
            f'(distinct clients this run)')
        rows = []
        for zone in sorted(segments):
            c = segments[zone]
            bits = [f"{c['dns']} via DNS" if "dns" in c else None,
                   f"{c['fw']} via firewall" if "fw" in c else None]
            rows.append(f'<li style="{_LI_STYLE}">{escape(zone)}: '
                        f'{escape(", ".join(b for b in bits if b))}</li>')
        add(f'<ul style="{_UL_STYLE}">' + "".join(rows) + '</ul>')
        add('</li>')
    for c in report.canaries:
        state = "detected" if c.detected else "<strong>NOT DETECTED</strong>"
        add(f'<li style="{_LI_STYLE}">canary {escape(c.name)}: {state} &mdash; '
            f'{escape(c.detail)}</li>')
    for note in report.data_quality:
        add(f'<li style="{_LI_STYLE}">{escape(note)}</li>')
    add('</ul>')

    add(f'<div style="{_FOOTER_STYLE}">Run {escape(report.run_id)} &mdash; generated '
        f'automatically, without human review. Do not reply to this message.</div>')

    add('</div></body></html>')
    return "\n".join(a) + "\n"


def _health_summary(report: Report) -> str:
    if not report.health:
        return "none configured"
    return ", ".join(f"{h.source} {h.state.value}" for h in report.health)


def _segment_client_counts(report: Report) -> dict[str, dict[str, int]]:
    """Distinct client population per zone, straight from the traffic itself -
    see the identical helper in render/plaintext.py for why."""
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


def _finding_html(f: Finding) -> str:
    border = _SEVERITY_COLORS.get(f.severity.label(), _MUTED)
    out = [f'<div style="{_FINDING_STYLE}border-left-color:{border};">']
    out.append(f'<p style="{_FINDING_TITLE_STYLE}">[{escape(f.severity.label())}] '
               f'{escape(f.id)} - {escape(f.title)}</p>')
    body = [
        ("Zone", f.zone), ("Confidence", str(f.confidence)),
        ("What", f.what), ("Why", f.why),
        ("Ruled out", f.not_this), ("Action", f.action),
    ]
    for label, value in body:
        if not value:
            continue
        out.append(f'<div style="{_DT_STYLE}">{escape(label)}</div>'
                   f'<div style="{_DD_STYLE}">{escape(value)}</div>')
    for ref in f.enrichment[:3]:
        out.append(f'<div style="{_DT_STYLE}">Reputation</div>'
                   f'<div style="{_DD_STYLE}">{escape(ref.summary)}</div>')
    if f.attribution_caveat:
        out.append(f'<div style="{_DT_STYLE}">Attribution</div>'
                   f'<div style="{_DD_STYLE}">{escape(f.attribution_caveat)}</div>')
    for adj in f.adjustments:
        out.append(f'<div style="{_DT_STYLE}">Adjusted</div>'
                   f'<div style="{_DD_STYLE}">{escape(adj)}</div>')
    out.append('</div>')
    return "".join(out)


def _statistics_table(report: Report) -> str:
    rows = []
    for m in report.metrics[:40]:
        prior = "-" if m.prior is None else f"{m.prior:g}"
        delta = m.delta_pct
        change = "-" if delta is None else f"{delta:+.0f}%"
        unit = f" {m.unit}" if m.unit else ""
        rows.append(
            f'<tr><td style="{_TD_STYLE}">{escape(m.display_label())}</td>'
            f'<td style="{_TD_STYLE}">{escape(str(m.value))}{escape(unit)}</td>'
            f'<td style="{_TD_STYLE}">{escape(prior)}</td>'
            f'<td style="{_TD_STYLE}">{escape(change)}</td></tr>'
        )
    if not rows:
        return f'<p style="{_P_STYLE}">No statistics were produced for this run.</p>'
    head = (f'<tr><th style="{_TH_STYLE}">Metric</th><th style="{_TH_STYLE}">Value</th>'
           f'<th style="{_TH_STYLE}">Prior</th><th style="{_TH_STYLE}">Change</th></tr>')
    return f'<table style="{_TABLE_STYLE}"><thead>{head}</thead><tbody>' + \
           "".join(rows) + '</tbody></table>'
