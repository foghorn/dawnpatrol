# Outputs

An output pairs a renderer with a destination. That split matters: renderers
(`plaintext`, `markdown`, `json`, `html`, `html_email`) are shared library code, not
plugins, so a new delivery destination inherits a correct, already-tested report body
instead of re-implementing formatting. `smtp_email`, `file_report`, `webhook`, and a
future `s3_upload` all get their format's contract right by construction, because none
of them format anything themselves.

Three ship today: `file_report` (always on), `smtp_email`, `webhook`.

## The contract

```python
# dawnpatrol/outputs/base.py
class Output(ABC):
    name: str
    renderer: str = "plaintext"          # "plaintext" | "markdown" | "html" | "html_email" | "json"
    requires_env: frozenset[str]
    default_run_when: frozenset[Status] = {GREEN, AMBER, RED}
    default_important_only: bool = False

    @abstractmethod
    def emit(self, rendered: str, report: Report, ctx: RunContext) -> DeliveryResult:
        """Deliver. Must not raise - return ok=False with a detail string instead."""
```

`should_run(report)` is already implemented on the base class and is what makes
delivery policy a config decision, not a code one:

```bash
DAWNPATROL_OUTPUT_<NAME>_RUN_WHEN=ALWAYS | NEVER | IMPORTANT | AMBER,RED
```

`IMPORTANT` means AMBER/RED, a failed canary, or an unhealthy source - `has_important()`
on `Report`. This is the mechanism behind "email every day, but only ping the phone when
something's actually wrong": same report, two outputs, two policies, zero code.

## Two things every output must get right

**Never raise.** An output that throws is a run that otherwise succeeded getting logged
as failed. Catch everything at the boundary and return `DeliveryResult(ok=False,
detail=...)` - `runner.py` logs it and moves on to the next output regardless.

**Respect `ctx.dry_run`.** `smtp_email.py` and `webhook.py` both check it and skip the
actual send, returning `skipped=True` with a description of what *would* have happened.
`file_report.py` deliberately does not check it - writing a local file has no real
"delivery" risk the way an external send does, and skipping it would make `--dry-run`
useless for inspecting what a run actually produced. Decide which behavior fits your new
output and say so in a comment; don't assume.

## Walkthrough: `smtp_email.py`

Plain `smtplib`, STARTTLS or SSL per `DAWNPATROL_OUTPUT_SMTP_STARTTLS`/`_SSL`. The
message is `multipart/alternative` with two parts, built with the standard library's
`EmailMessage`:

```python
message.set_content(render_with("plaintext", report), subtype="plain", charset="us-ascii")
message.add_alternative(rendered, subtype="html", charset="utf-8")   # rendered = html_email
```

`renderer = "html_email"` on the class is what the `rendered` argument to `emit()`
actually is; the plaintext part is rendered a second time, directly, inside `emit()`
itself, specifically so both parts exist regardless of which renderer the class declares
as primary. Every mail client that opens the message shows the HTML part - that's the
"preferred" alternative in MIME's ordering, formatted findings, colored status badge, a
real table for statistics; the plain-text part underneath is there for the minority of
clients that can't render HTML, for spam filters that weight a missing plaintext part
negatively, and for accessibility tools - never seen by a normal reader, never the thing
you're designing for, but there. Recipients come from `DAWNPATROL_OUTPUT_SMTP_TO`, an
environment variable, never from anything in the report body - the structural reason
log content can't redirect a delivery.

`html_email.py` is a separate module from the general-purpose `html.py` renderer used by
`file_report`/`webhook`, not a shared one, because email has a stricter rendering
contract than a browser or a webhook does: every mail client (Outlook's desktop client
renders through Word's engine, not a browser engine, in particular) has to be assumed
incapable of honoring a `<style>` block, so every rule in `html_email.py` is inlined
directly onto the element it applies to.

## Walkthrough: `webhook.py`

One HTTP POST, three body styles (`json` | `text` | `slack`) selected by
`DAWNPATROL_OUTPUT_WEBHOOK_STYLE`, defaulting to `important_only=True` - a channel that
pings every morning regardless of content gets muted, and a muted alert channel is worse
than none. The `json` style's payload includes the full markdown render and structured
findings, so a downstream automation (n8n, a SIEM ingest) has everything it needs
without a second API call back to DawnPatrol.

## A real gotcha worth knowing before you build one: file permissions

`file_report.py` writes into whatever `DAWNPATROL_OUTPUT_DIR` resolves to. In the
reference Docker deployment, the container runs as a fixed non-root user (the
Dockerfile's `USER` directive), but a bind-mounted host directory keeps the *host's*
ownership - so the very first write into a freshly bind-mounted `./out` fails with
`Permission denied` until the directory is made writable by that user
(`chmod o+w out`, done once by the deployment script). If your new output also writes to
a mounted path, this will bite you identically; if it only talks to a network endpoint
(webhook, SMTP), it never comes up.

## Build your own

Copy `dawnpatrol/outputs/TEMPLATE.py`.

```python
class HealthchecksOutput(Output):
    name = "healthchecks"
    renderer = "plaintext"      # unused if you never touch `rendered`
    requires_env = frozenset({"DAWNPATROL_OUTPUT_HEALTHCHECKS_URL"})
    default_run_when = frozenset({Status.GREEN, Status.AMBER, Status.RED})

    def emit(self, rendered, report, ctx) -> DeliveryResult:
        url = read_env("DAWNPATROL_OUTPUT_HEALTHCHECKS_URL", "")
        if ctx.dry_run:
            return DeliveryResult(output=self.name, ok=True, skipped=True,
                                  detail="dry run: would ping healthchecks.io")
        try:
            httpx.get(url, timeout=10)
        except Exception as exc:
            return DeliveryResult(output=self.name, ok=False, detail=str(exc)[:300])
        return DeliveryResult(output=self.name, ok=True, detail="pinged")
```

A dead-man's-switch output like this is the natural answer to "can GREEN days stay
quiet without that silence being ambiguous with a dead container" - it doesn't need the
rendered body at all, just a heartbeat on every completed run regardless of status.

### Wire it up and test it

```bash
DAWNPATROL_OUTPUT_HEALTHCHECKS_URL=https://hc-ping.com/... dawnpatrol run --print
dawnpatrol run --dry-run   # confirm it reports what it *would* do, without sending
```

Add a test in `tests/test_pipeline.py` alongside the existing output tests: run the
pipeline with your output in `settings.enabled_outputs`, and assert on
`outcome.deliveries` - both the success path and, by pointing at an unreachable URL, the
failure path returns `ok=False` rather than raising.
