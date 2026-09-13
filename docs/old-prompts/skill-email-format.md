---
name: netwatch-email-format
description: Renders a finished NetWatch network security report into the exact plain-text email body used for delivery, and sends it. Use this skill whenever a NetWatch or network security report is being emailed, whenever you are about to call send_email with a NetWatch report, or whenever a task mentions emailing/delivering a daily network, firewall, DNS, or security report. Contains the mandatory verbatim plain-text template, the substitution token list, the prohibited-characters list, and the pre-send checklist. Load this BEFORE composing any report email — the output is a fixed contract, not a matter of judgment. Trigger even if the request only says "email the report" or "send it."
---

<!--
SANITIZED COPY - published version of a NetWatch v1 agent file.

Removed information is marked inline with ***** REDACTED ***** markers.
In addition, and NOT marked inline because it appears on almost every line:

  * Internal RFC1918 subnets were remapped. The real ranges became
    10.0.10.0/24 (main LAN), 10.0.50.0/24 (IoT), 10.0.15.0/24 (DMZ).
    Host octets are unchanged, so every cross-reference in the prompt
    still lines up and the logic still reads correctly.

Everything else is verbatim. Third-party scanner addresses that appear as
worked examples (Google Cloud, Palo Alto Cortex Xpanse, a Tor exit node)
were left intact - they are public internet background noise, not mine.

See README.md in this folder for the full redaction inventory.
-->

# NetWatch Email Format

## The rule that overrides everything else here

The email body is **plain text only**. Not Markdown. Not HTML. Not "Markdown that
renders nicely." The recipient's client displays exactly the bytes you send, in a
font you do not control, at a width you do not control.

Call the email tool with HTML disabled (`html: false`, or omit the HTML flag
entirely). Never send an HTML body. Never send attachments. Never send a body that
links back to a note, a dashboard, or a chat session — the email stands alone.

## Do not write a script to build this

Do not write Python, shell, or any other code to render, convert, or assemble the
email body. Do not generate the body into a file and read it back. Renderers written
fresh each run produce different output each run — that is the exact failure this
skill exists to eliminate.

Instead: copy the template below into your reply, substitute the `{{TOKENS}}`, and
pass the result directly as the email tool's body parameter. The body is typed
content, not a build artifact.

Analysis code is still fine and expected — you need it to count 200,000+ records.
Confine it to *producing numbers*. Have it print values labeled with the exact token
names below, so filling the template is a lookup rather than a judgment call. Never
let analysis code emit prose, formatting, or the body itself.

## Why not ASCII tables

Tempting, and wrong. Many mail clients — Gmail mobile, Outlook mobile, Apple Mail in
some configurations — render `text/plain` in a **proportional** font. Every
space-aligned column, dot leader, and box-drawing border collapses into ragged
garbage. You cannot detect this from the sending side.

So: **one fact per line, `Label: value` form.** It survives any font, any width, any
client. Multi-column layouts and `|` pipes are prohibited for this reason, not as a
style preference.

## Prohibited in the body

Reject all of these. Each either renders as literal noise in plain text or breaks
across clients:

| Prohibited | Use instead |
|---|---|
| `#` headings | ALL-CAPS heading + `=====` underline |
| `**bold**`, `*italic*`, `_underscore_` | nothing; rely on structure |
| `` `backticks` ``, code fences | plain text, indented 2 spaces if needed |
| `|` pipe tables, aligned columns | one `Label: value` per line |
| `[text](url)` links | bare URL on its own line, or omit |
| `- ` / `* ` bullets | `  - ` is acceptable; never `*` |
| Em dash `—`, en dash `–`, smart quotes | ASCII hyphen `-`, straight quotes |
| Emoji, `✓`, `🟢`, box-drawing chars | `[OK]`, `[FAIL]`, `[CRITICAL]` etc. |
| Non-ASCII of any kind | ASCII only - gateways mangle the rest |
| Trailing whitespace | strip it; some clients show it as artifacts |

**ASCII-only, hard rule.** Prior runs emitted `✓`, `🟢`, and em dashes; these are the
characters most likely to arrive as `?` or mojibake through an unknown MTA.

Hard-wrap every line at **72 characters**. Do not rely on client wrapping.

## Fixed structure

Sections 1-10, always all ten, always this order, always these exact heading strings.
A section with nothing in it gets its documented empty-state line - never delete a
section, never add one, never reorder. The recipient scans the same shape every
morning; that predictability is the entire product.

## THE TEMPLATE - copy verbatim, substitute tokens only

Everything between the two BEGIN/END markers is the body. Do not include the markers.
Do not add a preamble, a sign-off, or commentary.

```
--- BEGIN TEMPLATE ---
NETWATCH DAILY REPORT
=====================

Report date:    {{REPORT_DATE_UTC}}
Window:         {{WINDOW_START_UTC}} to {{WINDOW_END_UTC}} UTC
Overall status: {{STATUS}}
Findings:       {{FINDING_COUNT}}
Data sources:   LibreNMS {{LIBRENMS_STATUS}} / Pi-hole {{PIHOLE_STATUS}}


1. EXECUTIVE SUMMARY
====================
{{EXEC_SUMMARY}}


2. KEY STATISTICS
=================
Windows differ by source. Firewall = 48h. DNS = ~24h (retention limit).

Firewall and router (48h):
  Total syslog messages:      {{SYSLOG_TOTAL}}
  Firewall DROPs:             {{DROPS}}
  Firewall ACCEPTs:           {{ACCEPTS}}
  System/service events:      {{SYSTEM_EVENTS}}
  Unique external source IPs: {{UNIQUE_SRC_IPS}}
  Peak DROP hour:             {{PEAK_HOUR}} ({{PEAK_HOUR_COUNT}})
  WAN link flaps:             {{WAN_FLAPS}}
  Router reboots:             {{REBOOTS}}
  VPN session events:         {{VPN_EVENTS}}

DNS ({{DNS_COVERAGE_HOURS}}h actual coverage):
  Total DNS queries:          {{DNS_TOTAL}}
  Queries blocked:            {{DNS_BLOCKED}}
  Block rate:                 {{DNS_BLOCK_RATE}}
  Unique domains queried:     {{DNS_UNIQUE_DOMAINS}}
  Active internal clients:    {{DNS_CLIENTS}}

Change vs prior run:
{{PRIOR_COMPARISON}}


3. FINDINGS
===========
{{FINDINGS_BLOCK}}


4. PERIMETER / FIREWALL ACTIVITY
================================
{{PERIMETER_BLOCK}}


5. ROUTER HEALTH AND REMOTE ACCESS
==================================
{{ROUTER_BLOCK}}


6. DNS ACTIVITY
===============
{{DNS_BLOCK}}


7. SEGMENT REVIEW
=================
7.1 Main LAN (10.0.10.0/24)
{{SEG_LAN}}

7.2 IoT (10.0.50.0/24, via 10.0.10.8)
{{SEG_IOT}}

7.3 DMZ (10.0.15.0/24, via 10.0.10.2)
{{SEG_DMZ}}


8. TREND WATCH
==============
{{TREND_BLOCK}}


9. RECOMMENDED ACTIONS
======================
{{ACTIONS_BLOCK}}


10. DATA QUALITY AND CAVEATS
============================
{{DATA_QUALITY_BLOCK}}


-- 
NetWatch automated report. Generated {{REPORT_DATE_UTC}} UTC.
Firewall data: LibreNMS 10.0.10.55. DNS data: Pi-hole 10.0.10.69.
--- END TEMPLATE ---
```

## Subject line

Plain ASCII, no Markdown, no emoji, exactly:

```
[NetWatch] Daily Report - {{YYYY-MM-DD}} - {{STATUS}} - {{FINDING_COUNT}} finding(s)
```

Use a plain hyphen as the separator. `STATUS` is `GREEN`, `AMBER`, or `RED`.

## Filling the variable blocks

**`{{STATUS}}`** - `GREEN`, `AMBER`, or `RED`. Bare word, no brackets, no colour, no
symbol.

**`{{EXEC_SUMMARY}}`** - two or three sentences, wrapped at 72 chars. Plain English.
Lead with whether anything needs doing today.

**`{{PRIOR_COMPARISON}}`** - two-space-indented `Label: this vs prior (change)` lines.
If no prior baseline exists, the entire block is exactly:

```
  No prior baseline available - first run or no retained history.
```

**`{{FINDINGS_BLOCK}}`** - if there are none, the block is exactly:

```
  No findings this period. Baseline internet background noise only.
```

Otherwise one entry per finding, severity-ordered CRITICAL to INFO, in this shape:

```
  [HIGH] F2 - Sustained SSH probe from 203.0.113.45
    Segment:    Perimeter (WAN)
    Confidence: High
    What:       4,812 DROPs to port 22 from a single source over 41
                hours, TCP SYN only, TTL consistent at 51.
    Why:        Single source, single fixed destination port, sustained
                over hours - matches persistent targeted prober, not the
                one-hit-per-IP pattern of a mass scanner sweep.
    Reputation: AbuseIPDB score 92/100, not whitelisted, Fixed Line ISP
                (Example Telecom), RO, last reported 2026-08-09.
                Corroborates; raised MEDIUM to HIGH.
    Not:        Not conntrack return traffic; source port varies and
                destination is a listening service port, not a high
                ephemeral port.
    Action:     Add a WAN drop rule for 203.0.113.45.
```

Severity tag in square brackets at line start. Labels indented 4, continuation lines
aligned under the label text. Keep `What/Why/Not/Action` on every finding MEDIUM and
above; LOW and INFO may use `What` and `Action` only.

**`{{PERIMETER_BLOCK}}`** - `Label: value` lines and short indented lists. Include
hourly DROP median/mean and any flagged spike with its attribution, protocol split,
WAN vs LAN ingress split, top destination ports by hit count and separately by unique
source count, and top source IPs each with its pattern classification. Mass-scanner
/24 sweeps get one line total, not a list. Annotate top source IPs with reputation inline, e.g.
`  198.235.24.27: 1,204 hits - score 0, whitelisted, Palo Alto Networks (scanner)`.
Mass-scanner sweeps still get one line total for the whole sweep, with the two
enriched representatives named. Never add a standalone reputation section or table.

**`{{ROUTER_BLOCK}}`** - reboots, WAN down/restored pairs with timestamps and outage
duration, watchdog and firmware events, VPN session events with times and peer IPs
separated from routine tunnel churn, and the emerg-severity-by-program breakdown so a
large emerg count is contextualised on the spot.

**`{{DNS_BLOCK}}`** - volume, block rate, top blocked domains with counts as
`  domain.example: 1,234` lines, top clients by volume and separately by block rate,
newly-observed domains, and any client resolving somewhere other than 10.0.10.69.
State the achieved coverage in hours here as well as in Section 10.

**`{{SEG_*}}`** - two to four lines each, indented two spaces. Where per-device
attribution was impossible because of gateway NAT, say so on its own line rather than
implying the segment was silent.

**`{{TREND_BLOCK}}`** - lines prefixed `  NEW: `, `  RECURRING: `, `  ESCALATING: `,
or `  RESOLVED: `. If no baseline exists, exactly:

```
  No prior run data. Trend analysis begins once a baseline exists.
```

**`{{ACTIONS_BLOCK}}`** - numbered `  1. ` etc., priority order, each with the
concrete rule or command where one applies. If there is nothing to do, the block is
exactly:

```
  No action required. Baseline noise only.
```

**`{{DATA_QUALITY_BLOCK}}`** - records retrieved per source, pagination
completeness, achieved coverage in hours per source, any API errors verbatim, and
anything unverified stated as unverified. Never smooth over a partial pull. 
State the number of IPs enriched, the max_age_in_days used, and any lookup failures.

The `Reputation:` line is required on every finding whose subject is an external IP,
and must state the score. Omit the line entirely for findings not about an external IP
- do not write "Reputation: n/a". If a lookup failed, write "Reputation: lookup
failed - see Section 10". Keep it to three wrapped lines maximum; ASCII only, no
score bars or symbols.

## Pre-send checklist - all must pass

Read your composed body and confirm:

1. No `{{` or `}}` remains anywhere.
2. No `#`, `**`, `` ` ``, `|`, `[](` sequences. (`[HIGH]`-style severity tags and the
   `-- ` signature separator are the only permitted bracket/dash markup.)
3. Body is pure ASCII. No emoji, no `✓`, no em dashes, no smart quotes.
4. No line exceeds 72 characters.
5. All ten section headings present, in order, spelled exactly as in the template.
6. Every empty section carries its documented empty-state line.
7. HTML is disabled on the send call. No attachments.
8. Subject matches the subject format exactly.
9. Every number in the body traces to the analysis output - nothing estimated,
   nothing recalled, nothing carried over from a previous run's figures.

## Sending

One email, one recipient, no CC or BCC. Read the tool response and confirm success.
On failure, retry once. If the second attempt fails, report the failure and the exact
error prominently in your final message - never describe an unsent report as
delivered. Do not send correction or follow-up emails; a mistake is corrected in the
next run.
```
