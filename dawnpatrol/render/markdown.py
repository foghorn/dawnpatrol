"""Markdown renderer, for destinations that render it (chat webhooks, files)."""

from __future__ import annotations

from ..models import Report

_BADGE = {"GREEN": "OK", "AMBER": "ATTENTION", "RED": "ACTION REQUIRED"}


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


def render(report: Report) -> str:
    out: list[str] = []
    a = out.append

    a(f"# DawnPatrol - {report.site_name}")
    a("")
    a(f"**Status:** {report.status.value} ({_BADGE.get(report.status.value, '')})  ")
    a(f"**Window:** {report.window.start_str} to {report.window.end_str} UTC "
      f"({report.window.hours:.2f}h)  ")
    a(f"**Findings:** {report.finding_count}  ")
    a(f"**Sources:** {', '.join(f'{h.source} {h.state.value}' for h in report.health)}  ")
    if report.canaries:
        a(f"**Detection self-test:** {report.canary_summary}  ")
    if report.degraded:
        a("")
        a("> AI analysis was unavailable for this run. Statistics only.")
    a("")

    a("## Executive summary")
    a("")
    a(report.executive_summary or "_No analysis narrative produced._")
    a("")

    a("## Findings")
    a("")
    if not report.findings:
        a("_No findings this period. Baseline activity only._")
    else:
        for f in report.findings_sorted():
            a(f"### `{f.severity.label()}` {f.id} - {f.title}")
            a("")
            a(f"- **Zone:** {f.zone}")
            a(f"- **Confidence:** {f.confidence}")
            if f.what:
                a(f"- **What:** {f.what}")
            if f.why:
                a(f"- **Why:** {f.why}")
            if f.not_this:
                a(f"- **Ruled out:** {f.not_this}")
            if f.action:
                a(f"- **Action:** {f.action}")
            for ref in f.enrichment[:3]:
                a(f"- **Reputation:** {ref.summary}")
            if f.attribution_caveat:
                a(f"- **Attribution:** {f.attribution_caveat}")
            for adj in f.adjustments:
                a(f"- _Adjusted: {adj}_")
            a("")
    a("")

    a("## Key statistics")
    a("")
    a("| Metric | Value | Prior | Change |")
    a("|---|---:|---:|---:|")
    for m in report.metrics[:40]:
        prior = "-" if m.prior is None else f"{m.prior:g}"
        delta = m.delta_pct
        change = "-" if delta is None else f"{delta:+.0f}%"
        unit = f" {m.unit}" if m.unit else ""
        a(f"| {m.display_label()} | {m.value}{unit} | {prior} | {change} |")
    a("")

    if report.trend_notes:
        a("## Trends")
        a("")
        for t in report.trend_notes:
            a(f"- **{t.kind}:** {t.text}")
        a("")

    if report.actions:
        a("## Recommended actions")
        a("")
        for i, action in enumerate(sorted(report.actions, key=lambda x: x.priority), 1):
            a(f"{i}. {action.text}")
            if action.command:
                a(f"   ```\n   {action.command}\n   ```")
        a("")

    a("## Data quality")
    a("")
    for h in report.health:
        a(f"- **{h.source}** - {h.state.value}, {h.records} records over "
          f"{h.span_hours:.2f}h (requested {h.requested_hours:.2f}h)")
        for note in h.notes[:5]:
            a(f"  - {note}")
    segments = _segment_client_counts(report)
    if segments:
        a("- **segment population** (distinct clients this run)")
        for zone in sorted(segments):
            c = segments[zone]
            bits = [f"{c['dns']} via DNS" if "dns" in c else None,
                   f"{c['fw']} via firewall" if "fw" in c else None]
            a(f"  - {zone}: " + ", ".join(b for b in bits if b))
    for c in report.canaries:
        a(f"- **canary {c.name}** - {'detected' if c.detected else '**NOT DETECTED**'}: {c.detail}")
    for note in report.data_quality:
        a(f"- {note}")
    a("")
    a("---")
    a(f"_Run `{report.run_id}` - generated automatically, without human review._")
    return "\n".join(out) + "\n"
