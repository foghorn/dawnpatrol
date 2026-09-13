---
name: domain-reputation-check
description: Looks up a domain's reputation, risk score, and threat
  classification using the ismalicious.com API. Use whenever a domain name
  (not an IP) needs to be checked for malicious activity, phishing, malware,
  blocklist hits, WHOIS/DNS/certificate history, or overall risk — including
  when another workflow (e.g. a log review or incident triage skill)
  encounters an unfamiliar domain and needs a verdict on it.
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

# Domain Reputation Check (ismalicious.com)

## Purpose
Given one or more domain names, return a clear, human-usable verdict:
malicious or not, risk level, why, and how confident that verdict is —
without dumping the raw API payload on the user.

## Calling the API
There is no SDK. Write a small temp Python script (or use `curl`) each time —
do not assume a script survives between runs.

```bash
curl -sS -G "https://api.ismalicious.com/check" \
  --data-urlencode "query=<DOMAIN>" \
  -H "X-API-KEY: *****REDACTED-ISMALICIOUS-API-KEY*****"
```

- One domain per request (`query=` takes a single value) — loop for multiple
  domains, respecting reasonable pacing (don't fire dozens simultaneously).
- The API key above is fixed for this integration; do not prompt the user for
  it or treat it as a placeholder.
- Response is large JSON (WHOIS, full certificate transparency history, DNS
  records, geo, MITRE ATT&CK mapping, OTX pulses, etc.). Parse it — never
  paste the raw JSON blob into a report or chat response.

## Fields that actually matter (read these, ignore the rest)

| Field | What it means |
|---|---|
| `malicious` | Top-level boolean verdict. This is the headline answer. |
| `riskScore.score` / `riskScore.level` | 0-100 score and low/medium/high/critical label. Primary risk signal. |
| `riskScore.summary` / `riskScore.factors[].description` | Human-readable reasons behind the score. Use these to explain "why." |
| `confidence.score` / `confidence.level` | How much to trust the verdict itself (source agreement, data completeness, freshness). |
| `blocklistHits` / `blocklistListed` | Count and boolean for threat-feed/blocklist matches. |
| `evidence.verdict` / `evidence.recommendedAction` / `evidence.reasons` | A pre-digested summary — often the fastest path to your final answer. |
| `dataTrust.providerAgreement` | Flags when sources disagree (see pitfall below). |
| `whois.domain.created_date` | Domain age — very young domains are a meaningful risk signal on their own. |
| `dns.hasSPF` / `hasDMARC` / `hasDKIM` / `emailPosture.grade` | Useful when the question is about phishing/spoofing risk specifically. |
| `geo` | Hosting location/ISP — context, not a verdict. |

## Critical pitfall: do not trust `classification.primary` alone

`classification.primary` (e.g. `"phishing"`, `"malware"`) is derived from
noisy, low-reliability signals — cheap indicators like "unusual certificate
common name pattern" (which fires on ordinary wildcard certs) and
low-reliability contextual OTX/blocklist scrapes. It can and does return a
high-confidence-looking classification like `phishing` at 90%+ confidence
for a domain the rest of the response clearly scores as low risk.

**Verified example:** `example.com` — a harmless, long-established,
Cloudflare-hosted domain — returned `malicious: false`, `riskScore.level:
"low"` (score 20), yet `classification.primary: "phishing"` at 93%
confidence. The `crossCorrelation` and `dataTrust.providerAgreement` sections
explicitly flagged the contradiction: "Feeds list entity; scanner sample
incomplete... Provider disagreement detected."

**Rule:** always anchor the verdict on `malicious`, `riskScore`, and
`evidence.verdict`/`recommendedAction`. Treat `classification.primary` as a
*secondary, unverified hypothesis* to mention only when it's corroborated by
`blocklistListed: true` with a decent `confidence.level`, or when
`dataTrust.providerAgreement.status` is `"agreement"` rather than
`"disagreement"`. Never report a domain as phishing/malware on the strength
of `classification` alone — that produces false positives.

## Output format

For a single domain, report:
1. **Verdict** — malicious yes/no, risk level, one-line reason.
2. **Confidence** — level and the one or two biggest drivers of it.
3. **Supporting detail** (only if relevant to why it was asked) — domain age,
   blocklist hits, hosting/geo, email auth posture.
4. **Caveat**, only if triggered — note when `classification.primary`
   disagrees with the risk score, per the pitfall above, so the reader knows
   not to over-index on it.

For a batch of domains, use a compact table: domain | malicious | risk level
| score | confidence | one-line reason.

## Error handling
- Non-200 response or malformed JSON: report the failure plainly, include
  the HTTP status, and do not fabricate a verdict.
- If a domain returns no data (`sources` empty, WHOIS null, etc.), say so —
  that itself is not evidence of maliciousness or safety either way.

## Using this from another skill
Other workflows (e.g. a firewall/DNS log review skill that surfaces an
unfamiliar domain in DNS query logs) should call this skill's procedure
rather than re-implementing the API call or the interpretation logic above —
in particular, they should inherit the "don't trust `classification.primary`
alone" rule so log-review reports don't get flooded with false phishing
findings sourced from noisy classifier output.
