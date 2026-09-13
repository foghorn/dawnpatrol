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

Scheduled NetWatch run. Generate today's daily network security report and email it.

Work window: the most recent 48 hours, ending now. Read the current time from a tool
first — do not assume the date.

CONNECTION DETAILS

LibreNMS (firewall + router syslog):
  All connection details, the API token, and the verified device_id table live in
  the `librenms-firewall-syslog-review` skill. Use them directly. There are no
  placeholders to fill and no credentials to wait for.

  Primary target: device_id=3 (ASUS RT-AX88U Pro, 10.0.10.1).
  Also pull device_id=4 (DMZ OpenWRT, 10.0.10.2) and device_id=7 (IoT OpenWRT,
  10.0.10.8) for segment visibility. device_id=8 (Windows Server) forwards no
  syslog — treat its silence as a known gap, not as "quiet."

  Every request needs the X-Auth-Token header. If you get HTTP 401, you forgot
  the header — add it and retry. Do NOT interpret a 401 as "LibreNMS is
  unreachable," and do NOT write a stub that reports failure without having made
  a real authenticated request. Only report NO DATA after an authenticated
  request has genuinely failed, and quote the exact request and response if so.

  DATE FORMAT: pass from/to as URL-encoded "YYYY-MM-DD HH:MM:SS" strings. Unix
  epoch integers return HTTP 200 with total=0 — a silent failure that looks
  exactly like a dead syslog feed. This exact bug has already caused one false
  outage report.

  If device 3 returns total=0, do NOT report an outage. Run the differential test
  in the skill: query device 3 with no time filter, and query devices 4 and 7 over
  the same window. Device 3 holds ~460,000 retained records and 75,000-85,000 per
  48h window. Zero is a bug in your request until all four probes say otherwise.

Pi-hole (DNS + blocked queries):
  Run the collection script in the `pihole-api-query` skill as written. Do not
  modify its pagination. Do not use the `cursor` parameter under any
  circumstances — it is a no-op on this instance and silently returns one page
  repeatedly.

  A correct pull is ~23 pages and ~222,000 records in under 15 seconds. If you
  end up with exactly 20,000 records, you used cursor pagination and must
  re-collect. If a page raises UnicodeDecodeError, your decode is missing
  errors="replace" — fix that and continue. Neither symptom means the API is
  broken or that offset pagination doesn't work.

  RETENTION: ~24h of DNS history is available regardless of the window
  requested. Collect what exists, state achieved coverage in hours in Section 10,
  and label the shortfall a known retention limit — NOT a collection failure and
  NOT a security finding. Never extrapolate 24h counts to a 48h figure.

IP reputation (AbuseIPDB):
  Use the `ip-reputation-enrichment` skill. Classify source IPs behaviourally from
  the firewall logs FIRST, then enrich at most 25 public IPs in as few batched
  check_ips calls as possible, with max_age_in_days: 90.

  Priority for the budget: persistent probers, proposed block candidates, VPN peer
  IPs, unexpected DMZ/IoT egress destinations, then top sources by volume. Never
  submit RFC1918 or other non-public addresses. Enrich two representatives of a
  mass-scanner /24 sweep, not the whole sweep.

  Read abuseConfidenceScore, not totalReports. Expect this network's largest
  talkers to carry thousands of abuse reports and score 0 because they are
  whitelisted cloud and security-vendor scanners — that CONFIRMS them as benign
  background noise. If enrichment fails or rate-limits, note it in Section 10 and
  continue; it is never a blocking dependency and never a finding.

EXECUTION NOTES
- Load both skills before starting; follow their procedures exactly, including
  pagination to completion and deduplication.
- Run the two collections in parallel. Give each its own output path under
  /var/tmp/netwatch/<RUN_DATE>/. Verify both files exist and are non-empty
  yourself before analyzing.
- Trend baseline comes from NOTES, not the filesystem. Search notes for titles
  starting "NetWatch State -" and read the most recent. The filesystem is wiped
  between runs, so an empty /var/lib or /var/tmp proves nothing about history.
  If no state note exists, label this run "first run - no baseline established"
  rather than inventing comparisons.
- Scratch files for this run may go under /var/tmp/netwatch/<RUN_DATE>/. Treat
  them as disposable; nothing there will exist tomorrow.
- Split the 48h FIREWALL window into two 24h halves for day-over-day comparison.
  DNS data covers only ~24h, so it supports no intra-run day-over-day split —
  compare DNS against the PRIOR RUN's state file instead, and say so explicitly.
  Never present a 24h DNS total alongside a 48h firewall total without labeling
  the differing windows.
- Pay particular attention to the IoT segment behind 10.0.10.8 and the DMZ Windows
  Server behind 10.0.10.2, and to any host querying DNS somewhere other than
  10.0.10.69.
- Before analyzing, verify each raw file's actual timestamp span covers the full
  48h window, and that unique record count matches the API-reported total. State
  the achieved coverage in Section 10. Expect ~75,000 syslog records from
  device 3 across roughly 16 paginated pages — if you have one page, you are not
  done.
- If a raw file already exists under /var/tmp/netwatch/<RUN_DATE>/ from an
  earlier attempt in this run, validate and use it. Never report NO DATA for a
  source whose valid output is already on disk.
- All timestamps on this host and in LibreNMS are UTC. Report in UTC. Do not
  convert to or label times as EDT/EST.
- The Pi-hole pull must pass its integrity checks before any DNS analysis: unique
  ID count == record count, unique count within 1% of recordsFiltered, and a
  computed timestamp span. The skill's script exits non-zero on failure — if it
  exits non-zero, DNS collection failed. Do not analyze its partial output and do
  not describe the run as successful.
- Never report a DNS record count without the achieved coverage in hours beside
  it.
- Reputation enrichment must not inflate the report. It should reduce noise, not
  manufacture findings. If enrichment moves the overall status, say explicitly in
  Section 3 which local behavioural evidence justified the finding independently of
  the score.

- Sanity-check every source total against the prior state note before analysing.
  Device 3 should return 75,000-85,000 records per 48h; Pi-hole ~200,000-222,000
  per ~24h. An order-of-magnitude deviation is a collection defect until proven
  otherwise — investigate your own pipeline before writing a finding about it.
- If you fix a collection bug during this run, state what you fixed in Section 10
  and record it in the state note. Fixes that live only in scratch scripts are
  lost when the filesystem is wiped and will be reintroduced tomorrow.

OUTPUT AND DELIVERY
1. Load the `netwatch-email-format` skill before composing the email. Build the
   body by copying its plain-text template verbatim and substituting values.
   Do NOT write a script to render or convert the body - paste the finished text
   directly into the send call.
2. EMAIL IT to *****REDACTED-RECIPIENT-EMAIL***** as PLAIN TEXT with HTML disabled. No
   Markdown, no HTML, no attachments, ASCII only, lines wrapped at 72 chars.
   One email, no CC/BCC. Send it whether the status is GREEN, AMBER, or RED, and
   send it even if a data source failed. Run the skill's pre-send checklist
   before sending.
3. Verify the send succeeded from the tool response. Retry once on failure; if it fails
   twice, say so loudly and `notify` about the delivery failure.
4. Save the report as a note, write the state file, and `notify` only if the status is
   AMBER/RED or the email failed.
5. Close your final message with the delivery confirmation line: recipient, subject
   sent, status.
6. Save the trend state note ("NetWatch State - <YYYY-MM-DD>") before finishing,
   so tomorrow's run has a baseline.

Be explicit in Section 10 about anything you could not retrieve, any placeholder that
was not filled in, and any part of the analysis that was limited as a result.
