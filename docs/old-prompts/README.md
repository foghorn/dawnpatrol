# NetWatch v1 — sanitized agent prompts and skills

These are the prompts and skills that drove the **first** version of this system:
an autonomous agent that pulled 48 hours of firewall syslog and ~24 hours of DNS
query logs off a home network every morning, correlated them, and emailed a
fixed-format plain-text report.

They are published as-is, warts included. The interesting parts are not the
network specifics — they are the accumulated scar tissue: the anti-fabrication
rules, the blocking differential tests, the "HTTP 200 is not evidence of
success" doctrine, and the email formatting contract. Almost every hard rule in
these files exists because the agent got something wrong once.

## The files

| File | What it is |
|---|---|
| `agent.md` | The system prompt. Network inventory, run procedure, severity model, report skeleton, hard rules. |
| `prompt.md` | The per-run task prompt fired by the scheduler. |
| `skill-librenms-log.md` | Skill: pulling and parsing iptables/kernel syslog out of LibreNMS. |
| `skill-pihole.md` | Skill: paginated Pi-hole v6 query-log collection, with the working collection script. |
| `skill-ip-reputation.md` | Skill: AbuseIPDB enrichment, lookup budget, severity guardrails. |
| `skill-domain-rep-check.md` | Skill: domain reputation lookups via ismalicious.com. |
| `skill-email-format.md` | Skill: the verbatim plain-text email template and pre-send checklist. |

Each file carries a sanitization notice at the top (after the YAML frontmatter,
where there is frontmatter).

## What was removed

Inline redactions are marked with `*****REDACTED-...*****` so you can see exactly
where something was taken out and what kind of thing it was.

| Marker | Was | Appears in |
|---|---|---|
| `*****REDACTED-LIBRENMS-API-TOKEN*****` | LibreNMS `X-Auth-Token` value | `skill-librenms-log.md` (5x) |
| `*****REDACTED-PIHOLE-API-PASSWORD*****` | Pi-hole `FTLCONF_webserver_api_password` | `skill-pihole.md` |
| `*****REDACTED-ISMALICIOUS-API-KEY*****` | ismalicious.com `X-API-KEY` | `skill-domain-rep-check.md` |
| `*****REDACTED-RECIPIENT-EMAIL*****` | The report recipient's address | `agent.md`, `prompt.md` |
| `*****REDACTED-HOSTNAME*****` | Two internal hostnames | `skill-librenms-log.md` |
| `*****REDACTED-DOMAIN*****` | A personal public domain | `skill-librenms-log.md` |
| `*****REDACTED-PUBLIC-IP*****` | That domain's public IP | `skill-librenms-log.md` |
| `*****REDACTED-WAN-IP-A/B*****` | Two observed router WAN IPs | `skill-librenms-log.md` |

## What was changed but not marked inline

**Internal RFC1918 subnets were remapped.** They appear on nearly every line, so
marking each one would have made the prompts unreadable. The real ranges became:

| Segment | Published as |
|---|---|
| Main LAN | `10.0.10.0/24` |
| IoT | `10.0.50.0/24` |
| DMZ | `10.0.15.0/24` |

Host octets are unchanged. `10.0.10.55` is still LibreNMS, `10.0.10.69` is still
Pi-hole, `10.0.10.8` is still the IoT gateway — every cross-reference in the
prompts still resolves and the logic still reads correctly.

## What was deliberately kept

Third-party addresses used as worked examples are real and were left intact.
They are public internet background noise that shows up in everyone's logs, and
the examples lose their point without them:

- `35.203.210.179` — Google Cloud scan infrastructure (whitelisted, score 0)
- `216.25.89.138` — Palo Alto Cortex Xpanse (whitelisted, score 0)
- `198.235.24.27` — Palo Alto scanner
- `185.220.101.1` — a Tor exit node (score 100)
- `203.0.113.45` — already an RFC 5737 documentation address in the original

## Note for anyone reusing these

Several files assert that the credentials they contain are "live, working
values" and instruct the agent not to treat them as placeholders. That language
was load-bearing — the agent kept refusing to run because it assumed the tokens
were unfilled templates — but in these published copies it is no longer true.
Substitute your own credentials before running anything here.
