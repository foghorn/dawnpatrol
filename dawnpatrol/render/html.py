"""HTML renderer, for destinations that render it (a browser, an HTML-capable
webhook, an archived copy next to the plaintext/JSON files).

Structurally the same report the plaintext and markdown renderers produce -
same fields, same ordering - just marked up. No JavaScript, no external
assets, no remote fonts: this has to render correctly offline, in a mail
client's stripped-down HTML view, or in a browser with no network access.
"""

from __future__ import annotations

from html import escape

from ..models import Finding, Report

_BADGE_CLASS = {"GREEN": "ok", "AMBER": "warn", "RED": "bad"}

_STYLE = """
body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;
     max-width:860px;margin:2rem auto;padding:0 1rem;color:#1b1f23;
     background:#fff;line-height:1.5}
h1{font-size:1.4rem;margin-bottom:.25rem}
h2{font-size:1.1rem;border-bottom:1px solid #d0d7de;padding-bottom:.3rem;
   margin-top:2rem}
.meta{color:#57606a;font-size:.9rem}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:.3rem;
       font-weight:600;font-size:.85rem}
.badge.ok{background:#dafbe1;color:#116329}
.badge.warn{background:#fff8c5;color:#7d4e00}
.badge.bad{background:#ffebe9;color:#82071e}
.finding{border-left:4px solid #d0d7de;padding:.25rem 0 .25rem 1rem;
         margin:1rem 0}
.finding.sev-CRITICAL,.finding.sev-HIGH{border-color:#cf222e}
.finding.sev-MEDIUM{border-color:#9a6700}
.finding.sev-LOW,.finding.sev-INFO{border-color:#57606a}
.finding dt{font-weight:600;color:#57606a;font-size:.85rem}
.finding dd{margin:0 0 .5rem 0}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #eaeef2}
th{color:#57606a;font-weight:600}
.notes li{margin-bottom:.35rem}
footer{color:#57606a;font-size:.8rem;margin-top:2rem;
       border-top:1px solid #d0d7de;padding-top:.75rem}
"""


def render(report: Report) -> str:
    out: list[str] = []
    a = out.append
    badge = _BADGE_CLASS.get(report.status.value, "")

    a("<!doctype html><html><head><meta charset=\"utf-8\">")
    a(f"<title>DawnPatrol - {escape(report.site_name)}</title>")
    a(f"<style>{_STYLE}</style></head><body>")

    a(f"<h1>DawnPatrol report - {escape(report.site_name)}</h1>")
    a('<p class="meta">')
    a(f'<span class="badge {badge}">{escape(report.status.value)}</span> ')
    a(f"Window {escape(report.window.start_str)} to {escape(report.window.end_str)} UTC "
      f"({report.window.hours:.2f}h) &middot; {report.finding_count} finding(s) &middot; "
      f"sources: {escape(_health_summary(report))}")
    if report.canaries:
        a(f" &middot; self-test: {escape(report.canary_summary)}")
    a("</p>")
    if report.degraded:
        a("<p><em>AI analysis was unavailable for this run. Statistics only.</em></p>")

    a("<h2>Executive summary</h2>")
    a(f"<p>{escape(report.executive_summary) or '<em>No analysis narrative produced.</em>'}</p>")

    a("<h2>Findings</h2>")
    if not report.findings:
        a("<p>No findings this period. Baseline activity only.</p>")
    else:
        for f in report.findings_sorted():
            a(_finding_html(f))
    if report.suppressed_findings:
        a(f"<p>{len(report.suppressed_findings)} finding(s) matched an active "
          f"suppression and were withheld:</p><ul class=\"notes\">")
        for f in report.suppressed_findings:
            a(f"<li>[{escape(f.severity.label())}] {escape(f.title)} "
              f"&mdash; <em>{escape(f.suppressed_reason)}</em></li>")
        a("</ul>")

    a("<h2>Key statistics</h2>")
    a(_statistics_table(report))

    if report.trend_notes:
        a("<h2>Trends</h2><ul class=\"notes\">")
        for t in report.trend_notes:
            a(f"<li><strong>{escape(t.kind)}:</strong> {escape(t.text)}</li>")
        a("</ul>")

    if report.actions:
        a("<h2>Recommended actions</h2><ol class=\"notes\">")
        for action in sorted(report.actions, key=lambda x: x.priority):
            a(f"<li>{escape(action.text)}")
            if action.command:
                a(f"<pre>{escape(action.command)}</pre>")
            a("</li>")
        a("</ol>")

    a("<h2>Data quality</h2><ul class=\"notes\">")
    for h in report.health:
        a(f"<li><strong>{escape(h.source)}</strong> &mdash; {escape(h.state.value)}, "
          f"{h.records} records over {h.span_hours:.2f}h "
          f"(requested {h.requested_hours:.2f}h)")
        if h.notes:
            a("<ul>" + "".join(f"<li>{escape(n)}</li>" for n in h.notes[:5]) + "</ul>")
        a("</li>")
    segments = _segment_client_counts(report)
    if segments:
        rows = []
        for zone in sorted(segments):
            c = segments[zone]
            bits = [f"{c['dns']} via DNS" if "dns" in c else None,
                   f"{c['fw']} via firewall" if "fw" in c else None]
            rows.append(f"<li>{escape(zone)}: {escape(', '.join(b for b in bits if b))}</li>")
        a("<li><strong>segment population</strong> (distinct clients this run)<ul>" +
          "".join(rows) + "</ul></li>")
    for c in report.canaries:
        state = "detected" if c.detected else "<strong>NOT DETECTED</strong>"
        a(f"<li>canary {escape(c.name)}: {state} &mdash; {escape(c.detail)}</li>")
    for note in report.data_quality:
        a(f"<li>{escape(note)}</li>")
    a("</ul>")

    a("<footer>")
    a(f"Run <code>{escape(report.run_id)}</code> &mdash; generated automatically, "
      f"without human review. Do not reply to this message.")
    a("</footer></body></html>")
    return "\n".join(out) + "\n"


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
    out = [f'<div class="finding sev-{escape(f.severity.label())}">']
    out.append(f"<h3>[{escape(f.severity.label())}] {escape(f.id)} - "
               f"{escape(f.title)}</h3>")
    out.append("<dl>")
    body = [
        ("Zone", f.zone), ("Confidence", str(f.confidence)),
        ("What", f.what), ("Why", f.why),
        ("Ruled out", f.not_this), ("Action", f.action),
    ]
    for label, value in body:
        if not value:
            continue
        out.append(f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>")
    for ref in f.enrichment[:3]:
        out.append(f"<dt>Reputation</dt><dd>{escape(ref.summary)}</dd>")
    if f.attribution_caveat:
        out.append(f"<dt>Attribution</dt><dd>{escape(f.attribution_caveat)}</dd>")
    for adj in f.adjustments:
        out.append(f"<dt>Adjusted</dt><dd>{escape(adj)}</dd>")
    out.append("</dl></div>")
    return "".join(out)


def _statistics_table(report: Report) -> str:
    rows = []
    for m in report.metrics[:40]:
        prior = "-" if m.prior is None else f"{m.prior:g}"
        delta = m.delta_pct
        change = "-" if delta is None else f"{delta:+.0f}%"
        unit = f" {m.unit}" if m.unit else ""
        rows.append(
            f"<tr><td>{escape(m.display_label())}</td>"
            f"<td>{escape(str(m.value))}{escape(unit)}</td>"
            f"<td>{escape(prior)}</td><td>{escape(change)}</td></tr>"
        )
    if not rows:
        return "<p>No statistics were produced for this run.</p>"
    return ("<table><thead><tr><th>Metric</th><th>Value</th><th>Prior</th>"
           "<th>Change</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
