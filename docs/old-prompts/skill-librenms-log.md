---
name: librenms-firewall-syslog-review
description: Queries and analyzes firewall/kernel syslog data pulled from this specific LibreNMS instance's syslog API (GET /api/v0/logs/syslog/{device_id}) — specifically iptables-style DROP/ACCEPT/REJECT lines from a router/firewall (e.g., ASUS/Broadcom-based routers, but the parsing pattern generalizes to any Linux iptables logging). Use this skill whenever the user asks to review, audit, or summarize firewall logs, syslog, security events, port scans, WAN traffic, VPN session activity, or "what's hitting my router" from a LibreNMS instance, or mentions a LibreNMS API token/URL alongside words like firewall, syslog, DROP, iptables, scanning, or intrusion. Also use it for time-boxed asks like "check the last 24/48 hours of firewall logs" or "any suspicious traffic on my router." Trigger this even if the user only gives connection details (base URL, token, device ID) without spelling out the full analysis — that's the signal this skill applies. All connection details and device IDs are contained in this skill; you do NOT need the user to supply them.
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

# LibreNMS Firewall/Syslog Review

## Purpose
Pull iptables-style kernel firewall log lines (and related router system/service
events) out of a LibreNMS device's syslog, then turn raw noise into an actionable
security summary: what's normal internet background scanning vs. what deserves a
closer look or a block rule.

## Connection details for this instance

**These are the live, working values. Use them as-is.** Do not wait for the user
to supply credentials, and do not treat an unfilled placeholder in a prompt as
evidence that no credential exists — this skill is the authoritative source.

| Setting | Value |
|---|---|
| Host / IP | `10.0.10.55` |
| Scheme | `http` (plain HTTP; no TLS configured) |
| API base URL | `http://10.0.10.55/api/v0` |
| Auth header | `X-Auth-Token: *****REDACTED-LIBRENMS-API-TOKEN*****` |
| Syslog endpoint | `GET /api/v0/logs/syslog/{device_id_or_hostname}` |
| Device list endpoint | `GET /api/v0/devices` |

### THE `from`/`to` FORMAT IS A SILENT DATA-LOSS TRAP — READ FIRST

`from` and `to` MUST be strings of the form `YYYY-MM-DD HH:MM:SS`, URL-encoded.
Passing **Unix epoch integers returns `HTTP 200` with `total: 0`** — no error, no
warning, no hint. It looks exactly like a device that stopped forwarding syslog.

Verified on this instance, same device, same 48h window, same moment:

```
from/to = "2026-08-09 09:16:09" / "2026-08-11 09:16:09"   ->  total = 84328   CORRECT
from/to = 1786598169 / 1786771369  (epoch ints)           ->  total = 0       SILENT FAILURE
from/to = "2026-08-09T09:16:09"    (ISO 8601)             ->  total = 84328   also works
from/to = "2026-08-09"             (date only)            ->  total = 79354   works, coarse
(no from/to at all)                                       ->  total = 462872  full retention
```

Build them with `datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")` and pass
them through `urllib.parse.urlencode` so the space becomes `+` or `%20`. Never
interpolate an epoch int. Never hand-build the query string with a raw space in it.

**`total: 0` from device 3 is a BUG IN YOUR REQUEST, not an outage.** Device 3
carries ~460,000 records of retained syslog and roughly 75,000-85,000 in any 48h
window. Zero is not a plausible reading. It has never once been a real outage on
this instance; it has twice been this exact format bug.

### MANDATORY DIFFERENTIAL TEST BEFORE REPORTING ANY LibreNMS FAILURE (blocking)

If device 3 returns `total: 0`, you have NOT established an outage. Run all four
checks and record every result before drawing any conclusion:

```bash
T="X-Auth-Token: *****REDACTED-LIBRENMS-API-TOKEN*****"
B="http://10.0.10.55/api/v0"

# 1. Same device, NO time filter. Proves whether syslog exists at all.
curl -s -H "$T" "$B/logs/syslog/3?limit=1"

# 2. Control devices, SAME window. Proves whether the window is the problem.
curl -s -H "$T" "$B/logs/syslog/4?from=2026-08-09+09:16:09&to=2026-08-11+09:16:09&limit=1"
curl -s -H "$T" "$B/logs/syslog/7?from=2026-08-09+09:16:09&to=2026-08-11+09:16:09&limit=1"

# 3. Re-issue device 3 with explicitly string-formatted, url-encoded dates.
curl -s -H "$T" "$B/logs/syslog/3?from=2026-08-09+09:16:09&to=2026-08-11+09:16:09&limit=1"

# 4. Narrow window (last 1h) with correct string format.
curl -s -H "$T" "$B/logs/syslog/3?from=<1h-ago-string>&to=<now-string>&limit=1"
```

Interpretation table — apply it, do not improvise:

| Observation | Conclusion |
|---|---|
| No-filter query returns data, windowed returns 0 | **Your date format is wrong.** Fix and re-collect. NOT an outage. |
| Devices 4/7 return data, device 3 returns 0, same window | Your device-3 request is malformed, OR router-only ingest gap. Keep testing. |
| No-filter query ALSO returns 0 on device 3 | Now a genuine ingest gap is plausible. Still check 4/7 before reporting. |
| ALL devices return 0 with no filter | Genuine LibreNMS-wide syslog failure. Report it. |
| Any request returns HTTP 401 | Missing auth header. Add it and retry. Never an outage. |

**Only the last two rows justify reporting a LibreNMS failure.** When you do,
quote all four probe results verbatim in your data-quality section, not just the
one that returned zero.

### `HTTP 200` is not evidence of a successful query

A 200 means the request was well-formed enough to parse. It says nothing about
whether your filters matched. On this endpoint the only real success signal is
**`total` > 0 with a record count and timestamp span you have inspected.** Never
write "the API responded 200 OK but returned zero records, therefore the data is
gone" — that inference is invalid on this endpoint and has produced a false outage
report.

### Sanity-check `total` against the known baseline

Before analysing, compare your `total` against these observed norms:

| Device | Expected 48h total | Action if far below |
|---|---|---|
| 3 (router) | 75,000 - 85,000 | Below ~10,000: assume a query bug, re-verify. Zero: run the differential test. |
| 4 (DMZ gw) | 600 - 2,500 | Low volume is normal here; zero is worth one line, not a finding. |
| 7 (IoT gw) | 1,400 - 3,500 | Low volume is normal here; zero is worth one line, not a finding. |
| 8 (Windows) | 0 always | Known gap, never a finding. |

A device-3 total that is orders of magnitude off baseline is a collection defect
until you have positively proven otherwise.

### AUTHENTICATION IS MANDATORY — READ THIS BEFORE YOUR FIRST CALL

**Every** request to this API requires the `X-Auth-Token` header. An
unauthenticated request returns `HTTP 401 {"error":"Unauthorized"}` on *every*
endpoint, including `/api/v0/devices`.

A 401 therefore means **your request was missing or misspelled the header** — it
does NOT mean the host is down, the token is invalid, or the data is unavailable.
Verified behavior:

```
curl -s -o /dev/null -w "%{http_code}" http://10.0.10.55/api/v0/devices
  → 401                                    # no header

curl -s -H "X-Auth-Token: *****REDACTED-LIBRENMS-API-TOKEN*****" \
     http://10.0.10.55/api/v0/devices
  → {"status":"ok","devices":[ ... 12 devices ... ]}
```

**On any 401, your required first action is to re-issue the identical request
with the header above.** Only after an authenticated request fails may you report
LibreNMS as unreachable, and you must quote the exact authenticated request and
response when you do.

### Never fabricate a failure
Do not write a script, stub, or function that *reports* an API failure without
actually issuing the request. If you cannot reach the API, the evidence is a real
HTTP response or a real socket error — nothing else counts. Reporting "NO DATA"
when a successful pull exists on disk is the single worst outcome for this skill.

## Device inventory (verified)

`device_id` values are stable on this instance. **The router is `device_id=3`.**
You do not need to run discovery to find it — but the discovery call is documented
below in case the inventory has changed.

| device_id | hostname / IP | Role | Syslog volume (48h, typical) |
|---|---|---|---|
| **3** | `10.0.10.1` | **ASUS RT-AX88U Pro — the firewall. Primary target.** | ~75,000 |
| 4 | `10.0.10.2` | OpenWRT gateway → DMZ (10.0.15.0/24) | ~2,300 |
| 7 | `10.0.10.8` | OpenWRT gateway → IoT (10.0.50.0/24) | ~3,500 |
| 8 | `10.0.15.135` | Windows Server (DMZ, TeamViewer host) | 0 — no syslog forwarding |
| 1 | `10.0.10.35` | generic host | low |
| 2 | `10.0.10.37` | macOS host | low |
| 5 | `10.0.10.32` | Linux host | low |
| 6 | `10.0.10.50` | `*****REDACTED-HOSTNAME*****` | low |
| 9 | `10.0.10.136` | ping-only host | low |
| 10 | `10.0.10.30` | `*****REDACTED-HOSTNAME*****` (Synology DSM) | low |
| 11 | `*****REDACTED-PUBLIC-IP*****` | `*****REDACTED-DOMAIN*****` (external, ping-only) | low |
| 12 | `10.0.10.38` | Linux host | low |

The endpoint accepts **either** the numeric id or the hostname —
`/api/v0/logs/syslog/3` and `/api/v0/logs/syslog/10.0.10.1` both work and return
identical data. Prefer the numeric id.

For a full-perimeter review, pull **device 3 (firewall) plus devices 4 and 7 (the
segment gateways)** — the OpenWRT gateways are the only visibility you have into
IoT and DMZ traffic. Device 8 forwards nothing; if a task needs Windows Server
events, report that gap rather than implying the segment is quiet.

### Optional: re-verify device discovery
Only needed if you suspect the inventory changed. Never a prerequisite for
collection, and never a reason to abort.

```bash
curl -s -H "X-Auth-Token: *****REDACTED-LIBRENMS-API-TOKEN*****" \
     http://10.0.10.55/api/v0/devices \
| python3 -c "import json,sys; [print(d['device_id'], d['hostname'], d.get('ip')) for d in json.load(sys.stdin)['devices']]"
```

If discovery fails but you still have the table above, **proceed with
`device_id=3`** and note the discovery failure in your data-quality section.
Never fall back to a guessed id such as `device_id=1` — on this instance id 1 is
an unrelated generic host and would silently produce a near-empty, wrong-device
report.

## Step 1 — Establish the time window
Compute `now` and `now minus N hours` (default 48h unless the user specifies a
different window) as `YYYY-MM-DD HH:MM:SS` strings. These become the `from` and
`to` query parameters. Always get the actual current timestamp from a tool/clock
rather than assuming — don't guess the date.

**Timezone:** this host's clock and the `timestamp` field returned by LibreNMS are
both **UTC**. Use naive local time (`datetime.fromtimestamp`), which on this host
is UTC, and label times in reports as UTC. Do not convert to EDT/EST or any other
zone, and do not append a timezone abbreviation you have not read from the clock —
a mislabeled window makes day-over-day comparison meaningless.

## Step 2 — Pull data with pagination
Endpoint: `GET http://10.0.10.55/api/v0/logs/syslog/{device_id}`
Header: `X-Auth-Token: *****REDACTED-LIBRENMS-API-TOKEN*****`
Query params: `from`, `to`, `limit=5000`, `start=<offset>`

- First call returns a `total` count in the JSON body alongside `logs`.
- If `total > 5000`, repeat with `start` incremented by 5000 (0, 5000, 10000, …)
  until you've covered `total`. A 48h window on device 3 is ~75,000 records —
  expect roughly 16 pages. **A single page is never a complete pull.**
- Merge all pages into a dict keyed by each entry's `seq` field to deduplicate —
  pages can overlap by a record at the boundary.
- `total` drifts upward between pages because syslog is ingested in real time.
  Guard the loop on `len(logs) < limit` **or** `offset >= total`, and treat a
  final unique count within ~1% of `total` as correct rather than an error.

### Mandatory pagination sanity check (blocking)
Before any analysis, assert all three:
1. Unique record count is within ~1% of the reported `total`.
2. `min(timestamp)` is within a few minutes of your window `from`.
3. `max(timestamp)` is within a few minutes of your window `to`.

If the min/max span is materially shorter than the requested window, **the pull is
truncated — fix it before analyzing.** Truncated data produces confidently wrong
conclusions (an hourly-distribution "spike" that is really just the only hour you
retrieved). Report the actual coverage you achieved, in hours, in your output.

Write a small Python script to do this rather than issuing dozens of manual
curl calls — it's faster and less error-prone.

### If you already have a raw file
Collection writes to `/var/tmp/netwatch/<RUN_DATE>/librenms_raw.json`. **Check for
and validate this file before re-collecting**, and before ever concluding data is
unavailable. If it exists, is non-empty, and passes the sanity check above, use
it. Reporting NO DATA while a valid pull sits on disk is a hard failure.

## Step 3 — Parse and categorize
Most entries have `program == "KERNEL"` and a `msg` field formatted like:
```
DROP IN=eth0 OUT= MAC=... SRC=<ip> DST=<ip> LEN=... TOS=... PREC=... TTL=<ttl> ID=... PROTO=<proto> SPT=<port> DPT=<port> ...
```
Extract with a regex capturing: action (DROP/ACCEPT/REJECT), `IN=` (ingress
interface), `SRC=`, `DST=`, `LEN=`, `TTL=`, `PROTO=`, `SPT=`, `DPT=`. Note
`PROTO=` sometimes appears as a raw protocol number (e.g. `2` for IGMP) instead
of a name — normalize/label these (2=IGMP, 1=ICMP, 6=TCP, 17=UDP) so protocol
breakdowns aren't fragmented by accident.

`DST=` on WAN-ingress drops is the router's **current dynamic public IP**. It
changes between and even within windows (both `*****REDACTED-WAN-IP-A*****` and
`*****REDACTED-WAN-IP-B*****` appear in a single recent 48h pull). Group by `SRC`/`DPT`, not
`DST`, and treat a `DST` change as an ISP lease renewal, not an incident.

Everything that isn't a KERNEL DROP/ACCEPT/REJECT line is a **system/service
event** — bucket these separately by `program`. Programs observed on this router,
by typical 48h volume: `KERNEL` (~67,000), `DNSMASQ-DHCP` (~4,600), `ROAMAST`
(~1,650), `HOSTAPD` (~950), `WLCEVENTD` (~220), `DBG` (~140), `DNSMASQ` (~90),
`AVAHI-DAEMON` (~45), **`VPNSERVER1` (~25)**, `WATCHDOG` (~25), `MINIUPNPD` (~20),
`CFG_SERVER` (~20), plus `REBOOT`, `WAN(0)`, `CROND`, `RC_SERVICE` when they
occur. These represent router health/DHCP/Wi-Fi activity, not firewall traffic,
and should be analyzed separately (mainly for reboots, WAN link flaps, and
watchdog/firmware events).

**`VPNSERVER1` is the OpenVPN remote-access server** and is the *only* source of
VPN session evidence in this dataset — always extract it when the task mentions
remote access. Lines are raw OpenVPN daemon output, e.g. tunnel setup/teardown
(`Closing TUN/TAP interface`, `/etc/openvpn/ovpn-route-pre-down tun21 …`), route
changes, and client authentication. Distinguish routine tunnel
init/down/interface churn from actual client auth events, and report peer IPs and
timing for the latter.

**Important severity caveat:** many ASUS/Broadcom-firmware routers mislabel
routine events (Wi-Fi mesh roaming/deauth via `ROAMAST`, debug lines via `DBG`,
routine scheduled firmware-check chatter via `WATCHDOG`) with `"emerg"`
severity. Don't treat a high count of `emerg`-level entries as alarming without
checking what `program`/`msg` actually produced them — break down "emerg"
entries by program before drawing conclusions.

## Step 4 — Analyze
Cover all of the following:

1. **Volume split**: total messages, firewall drop count vs. accept count vs.
   system/service log count.
2. **Hourly DROP distribution**: bucket by hour, compute median/mean, flag any
   hour that's well above the norm (e.g. >2x median) as a spike worth
   explaining — then check what source(s)/port(s) drove it. Only valid if the
   Step 2 sanity check confirmed full window coverage.
3. **Protocol breakdown** (TCP/UDP/ICMP/IGMP/other) and **ingress interface**
   breakdown (WAN vs. LAN interface names — on this router `eth0` = WAN,
   `eth1`/`br0` = LAN). LAN-side IGMP multicast noise (typically to
   `224.0.0.1`) is normal background chatter — summarize briefly, don't dig in.
4. **Destination ports**: top ~15-20 by raw hit count, AND top ports ranked by
   *unique source IP count* (a port hit by many distinct IPs is a broader
   scanning signal than the same hit count from one IP). Explicitly call out
   common attack-surface ports if present: 22 (SSH), 23 (Telnet), 80/443/8080/
   8443 (web/admin), 3389 (RDP), 445 (SMB), 5900 (VNC), 3306/5432 (databases),
   8728 (MikroTik API), 5060 (SIP), 1194/UDP (OpenVPN — this router runs a VPN
   server, so probes here are targeting a live service), and any other DB/
   management ports relevant to the deployment.
5. **Top source IPs by volume**, and for each notable one, classify the
   pattern using these heuristics:
   - **Single source, single fixed dest port, long sustained duration** (hours)
     = persistent targeted prober — worth flagging as a block candidate,
     especially against Telnet/SSH/RDP/VPN.
   - **Many IPs in the same /24, ~1 hit per IP each, broad/random dest ports,
     evenly spread over time** = mass internet scanner sweep (Shodan/Censys/
     commercial scan-engine class infrastructure) — normal background noise,
     no action needed.
   - **UDP, large fixed packet length (e.g. ~1500), TTL values incrementing in
     a stepped pattern (1,2,3,4…) across a burst** = possible spoofed/
     reflection/traceroute-style probing — treat with suspicion, note it, but
     don't over-alarm without more evidence.
   - **TCP sourced FROM port 80/443 hitting many random high ports on our
     side** = legitimate outbound session return traffic dropped by
     stateful-firewall/conntrack timeout — this is benign and should be
     labeled as such, not flagged as inbound attack traffic.
6. **Reputation enrichment.** After classifying patterns behaviourally, load the
   `ip-reputation-enrichment` skill and enrich the selected source IPs to corroborate
   or refute each classification. Classify first, enrich second — never let reputation
   lead, or you will chase scores instead of behaviour.

   Enrichment is expected to CONFIRM the mass-scanner heuristic: sweeps from this
   network's top talkers resolve to whitelisted Google Cloud and Palo Alto Networks
   (Cortex Xpanse) space with `usageType: Data Center/Web Hosting/Transit`. That is a
   settled benign classification, still worth one line, not a paragraph.

   Observe the skill's 25-IP budget. This window contains roughly 8,000 unique
   external sources; enriching them all is not possible and not useful.
7. **Total unique source IPs** in the window — this is the baseline volume of
   internet background scanning for the deployment; useful for comparison
   over time.
8. **WAN link flaps / reboots / watchdog events**: pull anything matching
   REBOOT, WAN link down/restored, or firmware watchdog programs, note exact
   timing, duration of any flap, and whether recovery was automatic and clean
   (e.g. an explicit "restored" message shortly after a "down" message).
9. **VPN session review** from `VPNSERVER1`: client connect/disconnect/auth
   events with timestamps and peer IPs, separated from routine tunnel churn.
10. **Day-over-day / prior-period comparison** if data is available: for
   recurring high-volume sources or subnet sweeps, note whether the pattern is
   new (appeared only in the most recent period), recurring (present at
   similar volume across periods), or escalating (materially increasing).

## Step 5 — Report format
Produce a concise report with these sections, in this order:

1. **Executive summary** (1-2 sentences) — is this normal background noise or
   is something actionable?
2. **Key stats table** — total messages, drop/accept/system split, unique
   source IPs, peak hour, WAN flap count, VPN session count, etc.
3. **Notable clusters/anomalies** — one entry per notable source/pattern with
   a brief technical explanation of *why* it's categorized the way it is
   (cite the SRC/DPT/PROTO/TTL/LEN/timing evidence, don't just assert it).
   For each notable source, add its reputation on the same line: score, whitelist
   status, ISP, usage type, and whether it confirms or contradicts the behavioural
   read. Never cite a report count without its score.
4. **Recommended actions** — be specific and proportionate: block/rate-limit a
   persistent single-source prober, investigate a WAN flap cluster if it
   recurs, otherwise explicitly say "no action needed" for baseline scanning
   noise rather than leaving it ambiguous.

State your achieved data coverage (records retrieved, actual timestamp span,
which device_ids) in the report. If any device pull was incomplete, say which
and by how much.

Keep the report focused on what's actionable — don't spend equal weight on the
mass-scanner /24 sweeps (normal, low-priority) as on sustained single-source
probes or genuine WAN instability (higher-priority).
