"""The plaintext renderer must satisfy a hard contract.

These assertions replace roughly 300 lines of the original system prompt. The
model can no longer violate the format because the model no longer writes it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from dawnpatrol.models import (
    UTC,
    Action,
    CanaryResult,
    Confidence,
    Entity,
    EntityType,
    Finding,
    HealthState,
    Metric,
    Report,
    Severity,
    SourceHealth,
    Status,
    TrendNote,
    Window,
)
from dawnpatrol.render import RENDERERS
from dawnpatrol.render import render as render_with
from dawnpatrol.render.plaintext import subject_line, to_ascii


def make_report(**kw) -> Report:
    end = datetime(2026, 6, 1, 6, 0, 0, tzinfo=UTC)
    window = Window(start=end - timedelta(hours=24), end=end)
    defaults = dict(
        run_id="20260601T060000Z-abc123",
        generated_at=end,
        window=window,
        status=Status.AMBER,
        site_name="testnet",
        executive_summary=(
            "One host began resolving an unfamiliar domain on a fixed 10 minute "
            "interval. Everything else is ordinary background scanning."
        ),
        metrics=[
            Metric(key="fw.drops", value=4812, section="perimeter",
                   label="Firewall DROPs", prior=4100.0),
            Metric(key="dns.total", value=222045, section="dns", label="DNS queries"),
            Metric(key="dns.block_rate", value=28.6, section="dns", unit="%",
                   label="Block rate"),
        ],
        health=[SourceHealth(source="pihole_dns", state=HealthState.DEGRADED,
                             records=222045, span_hours=23.99, requested_hours=24.0,
                             notes=["window clamped by retention"])],
        canaries=[CanaryResult(name="dns_beacon", detected=True, detail="ok")],
        actions=[Action(priority=1, text="Investigate 10.10.0.99.",
                        command="tcpdump -i br0 host 10.10.0.99")],
        trend_notes=[TrendNote(kind="NEW", text="First appearance of this pattern.")],
        data_quality=["DNS coverage 23.99h of a 24h window."],
    )
    defaults.update(kw)
    return Report(**defaults)


def sample_finding() -> Finding:
    return Finding(
        id="F1",
        title="Periodic DNS from 10.10.0.99 to steady-checkin.example.net",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        taxonomy="c2.beacon_candidate",
        zone="lan",
        what="72 queries at 600s intervals with under 2s of jitter.",
        why="Regular-interval resolution is the shape of an automated check-in.",
        not_this="Not NTP or an updater; no such software is installed on this host.",
        action="Capture traffic from this host and identify the process.",
        signal_ids=["beacon.dns.10.10.0.99.steady-checkin.example.net"],
        evidence_kinds=["local_behavior"],
        entities=[Entity(type=EntityType.IP, value="10.10.0.99")],
    )


# --------------------------------------------------------------------------- #
# The format contract
# --------------------------------------------------------------------------- #


def test_output_is_pure_ascii():
    body = render_with("plaintext", make_report(findings=[sample_finding()]))
    body.encode("ascii")  # raises if anything non-ASCII survived


def test_long_paragraphs_are_not_hard_wrapped():
    """A prior version hard-wrapped every paragraph to 72 columns, which
    double-wrapped against mail clients that already soft-wrap text/plain
    bodies to the reader's own width. The client decides now, not the
    renderer - a long sentence stays on one line."""
    long_sentence = (
        "This single sentence is deliberately much longer than seventy two "
        "characters so that a hard-wrapping renderer would have broken it "
        "across more than one line, which is exactly the behaviour we removed."
    )
    body = render_with("plaintext", make_report(executive_summary=long_sentence))
    assert long_sentence in body.split("\n")


def test_no_markdown_syntax_leaks_into_plaintext():
    body = render_with("plaintext", make_report(findings=[sample_finding()]))
    for token in ("**", "##", "```", "|---", "](", "~~"):
        assert token not in body, f"markdown token {token!r} in plaintext output"


def test_no_trailing_whitespace():
    body = render_with("plaintext", make_report(findings=[sample_finding()]))
    assert not [ln for ln in body.split("\n") if ln != ln.rstrip()]


def test_all_ten_sections_always_present():
    for report in (make_report(), make_report(findings=[sample_finding()])):
        body = render_with("plaintext", report)
        for n, name in enumerate([
            "EXECUTIVE SUMMARY", "KEY STATISTICS", "FINDINGS", "PERIMETER ACTIVITY",
            "ROUTER AND SYSTEM EVENTS", "DNS ACTIVITY", "SEGMENT REVIEW",
            "TREND WATCH", "RECOMMENDED ACTIONS", "DATA QUALITY AND CAVEATS",
        ], start=1):
            assert f"{n}. {name}" in body, f"section {n} ({name}) missing"


def test_empty_sections_carry_their_empty_state_line():
    body = render_with("plaintext", make_report(findings=[], actions=[], trend_notes=[]))
    assert "No findings this period" in body
    assert "No action required" in body


def test_no_unsubstituted_template_tokens():
    body = render_with("plaintext", make_report(findings=[sample_finding()]))
    assert "{{" not in body and "}}" not in body


@pytest.mark.parametrize("raw,expected", [
    ("em — dash", "em - dash"),
    ("word—word", "word-word"),
    ("“curly”", '"curly"'),
    ("arrow → here", "arrow -> here"),
    ("check ✓", "check [ok]"),
    ("emoji \U0001f7e2", "emoji ?"),
])
def test_transliteration_of_characters_that_mojibake(raw, expected):
    assert to_ascii(raw) == expected


def test_findings_are_ordered_by_severity():
    low = sample_finding()
    low.id, low.severity, low.title = "F2", Severity.LOW, "Lower severity item"
    report = make_report(findings=[low, sample_finding()])
    body = render_with("plaintext", report)
    assert body.index("[HIGH]") < body.index("[LOW]")


def test_adjustments_are_surfaced_not_hidden():
    f = sample_finding()
    f.adjustments = ["severity clamped HIGH -> MEDIUM"]
    body = render_with("plaintext", make_report(findings=[f]))
    assert "severity clamped" in body


def test_canary_failure_is_visible_in_the_header():
    report = make_report(canaries=[CanaryResult(name="dns_beacon", detected=False,
                                                detail="no signal produced")])
    body = render_with("plaintext", report)
    assert "0/1 canaries detected" in body
    assert "NOT DETECTED" in body


def test_suppressed_findings_are_disclosed_not_deleted():
    f = sample_finding()
    f.suppressed, f.suppressed_reason = True, "known vacuum telemetry"
    body = render_with("plaintext", make_report(findings=[], suppressed_findings=[f]))
    assert "suppression" in body.lower()
    assert "reason: known vacuum telemetry" in body


def test_subject_line_is_ascii_and_bounded():
    subject = subject_line(make_report())
    subject.encode("ascii")
    assert len(subject) <= 150
    assert "AMBER" in subject


# --------------------------------------------------------------------------- #
# Other renderers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_every_renderer_handles_an_empty_report(name):
    assert render_with(name, make_report(findings=[], metrics=[], health=[])).strip()


@pytest.mark.parametrize("name", sorted(RENDERERS))
def test_every_renderer_handles_a_populated_report(name):
    body = render_with(name, make_report(findings=[sample_finding()]))
    assert "steady-checkin.example.net" in body or "F1" in body


def test_json_renderer_is_valid_json():
    import json
    data = json.loads(render_with("json", make_report(findings=[sample_finding()])))
    assert data["status"] == "AMBER"
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["window"]["hours"] == 24.0


def test_degraded_report_says_so_plainly():
    body = render_with("plaintext", make_report(degraded=True, executive_summary=""))
    assert "statistics only" in body.lower()


# --------------------------------------------------------------------------- #
# HTML renderer
# --------------------------------------------------------------------------- #


def test_html_renderer_produces_a_full_document():
    body = render_with("html", make_report(findings=[sample_finding()]))
    assert body.strip().startswith("<!doctype html>")
    assert "</html>" in body


def test_html_renderer_escapes_attacker_influenced_text():
    """Finding text can contain log-derived strings; they must never inject markup."""
    f = sample_finding()
    f.why = "Domain observed: <script>alert(1)</script> & friends"
    body = render_with("html", make_report(findings=[f]))
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body


# --------------------------------------------------------------------------- #
# HTML email renderer
# --------------------------------------------------------------------------- #


def test_html_email_renderer_produces_a_full_document():
    body = render_with("html_email", make_report(findings=[sample_finding()]))
    assert body.strip().startswith("<!doctype html>")
    assert "</html>" in body


def test_html_email_renderer_has_no_style_block():
    """A <style> block is not reliably honoured by mail clients (Outlook's
    Word-based renderer in particular) - every rule here must be inline."""
    body = render_with("html_email", make_report(findings=[sample_finding()]))
    assert "<style" not in body
    # Every element carries its own style attribute rather than a class.
    assert 'style="' in body
    assert "class=" not in body


def test_html_email_renderer_escapes_attacker_influenced_text():
    f = sample_finding()
    f.why = "Domain observed: <script>alert(1)</script> & friends"
    body = render_with("html_email", make_report(findings=[f]))
    assert "<script>alert" not in body
    assert "&lt;script&gt;" in body


def test_html_email_renderer_colors_status_and_severity():
    red_report = make_report(status=Status.RED, findings=[sample_finding()])
    body = render_with("html_email", red_report)
    assert "#ffebe9" in body  # RED status badge background
    assert "#cf222e" in body  # HIGH severity finding border


def test_html_email_is_the_smtp_output_renderer_with_a_plaintext_fallback():
    """The email must render as multipart/alternative: HTML as the preferred
    part a normal client shows, plain text underneath as the fallback."""
    from dawnpatrol.outputs.smtp_email import SMTPEmailOutput

    assert SMTPEmailOutput.renderer == "html_email"


def test_smtp_output_sends_multipart_alternative_html_and_plaintext(monkeypatch):
    import smtplib
    import types

    from dawnpatrol.outputs.smtp_email import SMTPEmailOutput

    monkeypatch.setenv("DAWNPATROL_OUTPUT_SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("DAWNPATROL_OUTPUT_SMTP_TO", "you@example.invalid")

    sent: list = []

    class FakeSMTP:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, *a, **kw):
            pass

        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    report = make_report(findings=[sample_finding()])
    html_body = render_with("html_email", report)
    output = SMTPEmailOutput()
    ctx = types.SimpleNamespace(dry_run=False)
    result = output.emit(html_body, report, ctx)

    assert result.ok
    assert len(sent) == 1
    message = sent[0]
    assert message.is_multipart()
    parts = {part.get_content_type(): part for part in message.walk()
            if not part.is_multipart()}
    assert "text/plain" in parts
    assert "text/html" in parts
    assert "<!doctype html>" in parts["text/html"].get_content()
    assert sample_finding().title in parts["text/plain"].get_content()
