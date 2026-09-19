# Signal catalog

Every signal any analyzer currently emits, in one place. A **signal** is a deterministic
candidate finding — computed from real events, not yet judged (see
[analyzers.md](analyzers.md) for the full contract). This file is the reference for what
the model actually sees each run: every `Signal` object here is serialized into the
evidence bundle (`agent/bundle.py`) and handed to the investigate stage, and **every
`Finding` the model produces must cite at least one signal id** — `adjudicate.py` rejects
one that doesn't, structurally. If something isn't listed here, the model has no way to
report it as a finding, only to notice it in a metric or raw query and say so in
`data_quality_notes`.

This is a snapshot, not a spec — it will drift the moment an analyzer changes. Regenerate
it (or at least re-check it) whenever a signal is added, renamed, retuned, or removed;
`grep -n "r.signals.append(Signal(" dawnpatrol/analyzers/*.py` finds every one of them in
the current code if you need to verify this file against reality.

**Reading the tables:** *Signal ID pattern* is `id=` as constructed in code — a literal
value fires once per run at most, a `<placeholder>` can fire multiple times (once per
distinct value that meets the threshold). *Severity* is `severity_hint` — the
deterministic starting point; the model may adjust it, but `adjudicate.py` clamps any
raise to at most one level above the hint and never allows CRITICAL without local
evidence. *Confidence* is the analyzer's own `confidence`, 0–1. Sections are ordered by
each analyzer's `order` (its actual run sequence), not alphabetically.

---

## `firewall_volume` (order 10)

Perimeter statistics — the numbers section 2 of every report is built from. Deliberately
produces almost no signals: volume is context, not a finding, so the only thing it flags
is shape that genuinely breaks from the run's own pattern.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `fw.spike.<hour>` | `volume.spike` | LOW | 0.55 | Hourly DROP count in the peak hour exceeds 3× the run's own median, with ≥6 hours of coverage to make a median meaningful | `hour`, `count`, `median_hourly`, `multiple_of_median`, `hours_observed`, `top_sources_in_window` |

## `firewall_patterns` (order 20)

Behavioral classification of firewall sources, from local evidence only — reputation is
applied later by the model and can only corroborate, never lead. Four shapes; three
produce signals, the fourth (conntrack return traffic) is deliberately just a metric and
a note, since it's benign by construction.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `fw.sweep.<prefix>` | `scan.mass_sweep` | INFO | 0.8 | ≥15 distinct sources in one `/24` hit the perimeter, averaging ≤4 hits/source — commercial scan infrastructure shape | `prefix`, `distinct_sources`, `total_hits`, `hits_per_source` |
| `fw.prober.<ip>.<port>` | `scan.persistent_prober` | LOW, or MEDIUM if the top port is a declared attack-surface port | 0.6, or 0.75 if MEDIUM | One source, ≥50 hits, ≥2h duration, ≤3 distinct destination ports, ≥70% of hits on one port | `hits`, `duration_hours`, `first_seen`, `last_seen`, `distinct_destination_ports`, `top_port`, `top_port_hits`, `port_concentration`, `ttl_range`, `targets_attack_surface_port`, `prior_runs_with_this_source` |
| `fw.stepped_ttl.<ip>` | `scan.stepped_ttl` | LOW | 0.5 | UDP source, TTL min ≤8 and TTL range ≥4 across ≥10 hits — traceroute-style mapping or a spoofed reflection probe | `hits`, `ttl_range`, `distinct_destination_ports`, `duration_hours` |

Sweep members are computed first and excluded from prober classification, so one sweep
is never double-reported as dozens of individual probers.

## `dns_anomalies` (order 30)

DNS is usually the most compromise-relevant telemetry available, so this analyzer does
the most real detection: novelty, DGA shape, resolver-policy violation, two flavors
of per-client outlier, and two DNS tunneling shapes (subdomain fan-out, TXT/NULL
concentration).

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `dns.novel_domains` | `dns.novel_domain` | INFO | 0.7 | One or more domains never seen before this run (excludes the profile's benign-domain allowlist); suppressed entirely on the very first run, when everything looks novel | `novel_count`, `top_novel` (domain + query count, up to 25) |
| `dns.dga_candidates` | `dns.dga_suspect` | LOW | 0.45 | One or more domains whose leftmost label is long (≥12 chars), high-entropy (Shannon entropy ≥3.6), and either vowel-poor or digit-heavy | `count`, `top` (domain, queries, entropy, label_length) |
| `dns.resolver_bypass` | `dns.resolver_bypass` | HIGH | 0.85 | An internal host queries port 53 on a DNS server that isn't in `profile.yml`'s `approved_resolvers` | `approved_resolvers`, `observed` (client→resolver pairs + query counts) |
| `dns.block_outlier.<client>` | `dns.client_block_outlier` | LOW | 0.6 | One client's Pi-hole block rate is ≥60% *and* ≥2.5× the network's mean rate (min 200 queries to qualify) | `client`, `queries`, `blocked`, `block_rate_pct`, `network_mean_block_rate_pct`, `attribution_caveat` |
| `dns.nxdomain_outlier.<client>` | `dns.nxdomain_outlier` | LOW | 0.5 | One client's NXDOMAIN rate is ≥15% *and* ≥4× its peers' mean (peers exclude the client itself, to avoid the outlier inflating its own baseline); min 30 NXDOMAIN responses and 200 total queries | `client`, `queries`, `nxdomain`, `nxdomain_rate_pct`, `peer_mean_nxdomain_rate_pct`, `attribution_caveat` |
| `dns.tunnel_suspect.<client>.<apex>` | `dns.tunnel_suspect` | MEDIUM | 0.5–0.9 (scales with uniqueness ratio and subdomain count) | One client resolves ≥40 distinct subdomains of one non-benign apex, and distinct subdomains are ≥80% of total queries to that apex (near-1:1 - each query mostly unique, the core tunneling shape) | `client`, `apex`, `distinct_subdomains`, `total_queries`, `uniqueness_ratio`, `sample_subdomains`, `attribution_caveat` |
| `dns.tunnel_qtype_candidates` | `dns.tunnel_qtype_suspect` | MEDIUM | 0.5 | One or more non-benign domains have ≥20 TXT/NULL queries *and* TXT/NULL is ≥50% of that domain's total query volume - the classic payload-carrying record types for DNS tunneling tools | `count`, `top` (domain, txt_null_queries, total_queries, ratio_pct) |

## `novel_clients` (order 35)

First-ever-appearance detection for internal devices, by two independent identities so
DHCP lease churn doesn't cause false "new device" noise. Silent entirely on the first
run ever (everything looks new), since that would just be a wall of noise, not signal.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `net.novel_client.<zone>` | `net.novel_client` | LOW, or MEDIUM for untrusted/semi-trusted/dmz/guest zones | 0.55 | One or more internal IPs (DNS client or firewall source) never seen before, grouped by the zone they belong to | `zone`, `trust`, `count`, `ips` (labeled, up to 15/zone) |
| `net.novel_device_mac` | `net.novel_device_mac` | LOW | 0.5 | One or more MAC addresses (from DHCP lease lines or Wi-Fi deauth events, shape-validated so a Windows account name is never mistaken for one) never seen before — survives a device's IP changing on lease renewal | `count`, `macs` (up to 20) |

## `beaconing` (order 40)

Periodicity detection — the most reliable behavioral evidence of live C2 available
without endpoint telemetry. Works on DNS query timing today; gets substantially stronger
the moment a flow source is configured, since flow timing isn't diluted by DNS caching.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `beacon.dns.<client>.<domain>` | `c2.beacon_candidate` | MEDIUM | 0.45–0.95 (scales with tightness of interval and sample count) | A (client, domain) pair's DNS query gaps cluster tightly: coefficient of variation ≤0.18, ≥12 samples spanning ≥3h, mean interval 30s–2h | `client`, `domain`, `interval_seconds`, `jitter_seconds`, `coefficient_of_variation`, `samples`, `span_hours`, `attribution_caveat`, `prior_runs_with_this_domain` |
| `beacon.flow.<src>.<dst>` | `c2.beacon_candidate` | HIGH | up to 0.95 | Same periodicity test applied to flow-record connection timing between an internal source and external destination — only possible when a flow source is configured | `src`, `dst`, `interval_seconds`, `jitter_seconds`, `coefficient_of_variation`, `samples`, `span_hours`, `attribution_caveat` |

## `auth_activity` (order 45)

Authentication-adjacent events across every source that produces them: VPN daemon
lifecycle, Wi-Fi deauthentication, Windows logon/Defender telemetry, Linux SSH, and
router/gateway web-UI admin login. The largest signal surface of any analyzer, added
incrementally as each data source was confirmed live against real production data (see
the module's own docstring for the verification history of each subsection).

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `auth.vpn_restart_frequency` | `auth.vpn_instability` | LOW | 0.4 | VPN daemon lifecycle-line volume is ≥3× the prior run and ≥30 total. Counts restarts, never logins — this deployment's VPN log has no per-session data | `events_this_run`, `prior_run_events` |
| `auth.deauth_outlier.<mac>` | `auth.deauth_outlier` | LOW | 0.5 | One device's deauth count is ≥4× the peer median (peers exclude itself) and ≥10, with ≥20 total deauth events in the run | `mac`, `deauth_count`, `peer_median_deauths`, `distinct_devices_this_run` |
| `auth.mass_deauth.<timestamp>` | `auth.mass_deauth_burst` | MEDIUM | 0.55 | ≥6 distinct MACs deauthenticated within any 5-minute sliding window — the shape of a deauth-flood attack against the AP itself | `window_start`, `window_minutes`, `distinct_devices`, `macs` |
| `auth.windows_new_account` | `auth.windows_new_account` | MEDIUM | 0.55 | A never-seen-before Windows account authenticated (any logon action) on a host forwarding Security auditing | `accounts` |
| `auth.windows_external_logon.<src_ip>` | `auth.windows_external_logon` | HIGH | 0.7 | A *successful* Windows logon whose source address is outside the network, and whose logon type carries a real source address (network/rdp/net_clear) | `src_ip`, `account`, `logon_type`, `device` |
| `auth.windows_logon_failure_burst` | `auth.windows_logon_failure_burst` | MEDIUM | 0.5 | ≥5 failed Windows logons this run. Structurally ready; unverified against real failure data as of when it was built | `failed_logons`, `by_account` |
| `endpoint.defender_detection` | `endpoint.malware_detection` | HIGH | 0.75 | Windows Defender emitted a message matching its actual detection template ("...has detected malware or other potentially unwanted software") — matched *positively*, not by excluding known-benign wording, after that inverse approach produced two real false positives in production | `count`, `librenms_device_ids` (LibreNMS numeric ids, not hostnames), `messages` (first 300 chars each) |
| `auth.ssh_new_account` | `auth.ssh_new_account` | MEDIUM | 0.55 | A never-seen-before account authenticated over SSH (accepted) | `accounts` |
| `auth.ssh_external_logon.<src_ip>` | `auth.ssh_external_logon` | HIGH | 0.7 | A *successful* (accepted) SSH logon whose source address is outside the network | `src_ip`, `account`, `method`, `device` |
| `auth.ssh_failure_burst` | `auth.ssh_failure_burst` | MEDIUM | 0.6 | ≥5 failed or invalid-user SSH attempts this run — the classic brute-force/spray signature | `failed_attempts`, `by_source`, `by_account` |
| `auth.router_admin_external_login.<src_ip>` | `auth.router_admin_external_login` | HIGH | 0.7 | A *successful* router/gateway web-UI admin login (LuCI or the ASUS-family GUI) whose source address is outside the network | `src_ip`, `account`, `device` |
| `auth.router_admin_failure_burst` | `auth.router_admin_failure_burst` | MEDIUM | 0.6 | ≥5 failed router/gateway admin login attempts this run. Structurally ready; unverified against a real burst as of when it was built | `failed_attempts`, `by_source` |

## `segment_review` (order 50)

Per-zone review driven entirely by `profile.yml` — nothing here knows what "IoT" means,
only what the profile declares about trust, gateways, and expected egress, so the same
code reviews any network's zone layout unchanged.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `zone.<name>.unexpected_egress` | `segment.unexpected_egress` | LOW, or MEDIUM for untrusted/semi-trusted/dmz/guest zones | 0.6 | A zone with a declared `expected_egress_domains` list resolved one or more domains outside that set (and not on the global benign allowlist) | `zone`, `trust`, `expected`, `unexpected` (domain + query count), `attribution_caveat` |
| `zone.<name>.inbound_accepted` | `segment.inbound_accepted` | HIGH for untrusted zones (any accepted inbound), MEDIUM for trusted zones (novel source only) | 0.8, or 0.6 for the novelty-gated case | An external source had a firewall-*accepted* inbound session into the zone. For trusted zones this is novelty-gated (a source never seen reaching this zone before) so a standing, intentional port-forward doesn't fire every run | `zone`, `trust`, `novel_sources_only`, `accepted` (src, dst_port, hits) |
| `zone.<name>.daypart_anomaly.<daypart>` | `segment.time_of_day_anomaly` | LOW, or MEDIUM for untrusted/semi-trusted/dmz/guest zones | 0.5 | A zone historically quiet (≤5 mean events, ≥5 days of its own history) during one of four site-timezone dayparts (night/morning/afternoon/evening) sees a real burst there: ≥20 events this run *and* ≥4× the historical mean | `zone`, `daypart`, `events_this_run`, `historical_mean`, `history_days_observed`, `site_timezone` |

## `correlation` (order 60)

Cross-source analysis — the highest-value tier, and the one that only works because
every source normalizes into one `Event` shape. Also the mechanism that turns a prior
run's watchlist into something that can actually re-fire.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `corr.watchlist.<type>.<value>` | `watchlist.hit` | MEDIUM | 0.7 | An entity (`ip`, `domain`, or `host`) the model carried forward on a prior run's watchlist (`watchlist_updates`) shows activity again this run. `host` matches the same way `ip` does — by address — plus `Event.device`, in case some future source populates that with a real hostname | `entity`, `entity_type`, `events_this_period`, `watch_reason`, `watch_expires` |
| `corr.internal_scan.<ip>` | `lateral.internal_scan` | HIGH | 0.65 | An internal host probes ≥20 distinct destination ports with ≥50 total hits — the shape of lateral-movement enumeration, only visible when internal traffic actually traverses a logging device | `src`, `hits`, `distinct_destination_ports`, `duration_hours` |

## `data_volume` (order 55)

Outbound byte-volume signals, from `pkt_len` on ACCEPTed firewall events -
the closest thing to exfiltration detection possible without a flow source.
Validated against this deployment's live feed before being written: as of
2026-09, the edge router logs zero internal-to-external ACCEPT lines at all
(everything logged is internal-to-internal), and both segment gateways log
DROP/REJECT only, never ACCEPT. So on this network today this analyzer
correctly reports a near-zero `fw.bytes.outbound_accepted` metric and raises
nothing - a confirmed telemetry gap, not a bug - and activates the moment
that gap closes (an explicit egress-ACCEPT log rule, or a flow source), with
no code changes needed. See the module docstring for the full validation.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `data.volume_outlier.<src_ip>` | `data.volume_outlier` | MEDIUM | 0.5 | An internal source's total outbound-accepted bytes are ≥50MB *and* ≥5× the mean of its peers (≥3 sources with any egress required for a peer comparison) | `src`, `outbound_accepted_bytes`, `network_mean_bytes`, `multiple_of_mean`, `attribution_caveat` |
| `data.large_transfer.<src_ip>.<dst_ip>` | `data.large_transfer` | MEDIUM if the destination is novel, else LOW | 0.6 novel / 0.45 known | A single (source, destination) pair's outbound-accepted bytes reach ≥200MB in one run | `src`, `dst`, `bytes`, `hits`, `destination_is_novel`, `attribution_caveat` |

`pkt_len` is a per-packet length (iptables' `LEN=` field), not a
per-connection byte total - every signal here is directional evidence, never
a byte-accurate count, and both `narrative_hint`s say so explicitly.

## `baseline_delta` (order 900)

Runs last, after everything else, so it can compare this run's own metrics against
history. The only analyzer whose entire job is flagging *the analysis itself* as
possibly untrustworthy, rather than flagging something on the network.

| Signal ID pattern | Taxonomy | Severity | Confidence | Fires when | Key evidence |
|---|---|---|---|---|---|
| `trend.anomaly.<metric_key>` | `dataquality.magnitude_shift` | LOW | 0.5 | One of six watched metrics (`fw.drops`, `fw.unique_sources`, `dns.total`, `dns.blocked`, `dns.unique_domains`, `beacon.candidates`) moved ≥10× versus the prior run, in either direction — far more often a collection defect than a real event | `metric`, `prior`, `current`, `ratio` |

---

## What never becomes a signal

Some real, useful things this session confirmed working never reach this table by
design, because they're context or plumbing, not a candidate finding:

- **Reputation lookups** (`enrich_ip`/`enrich_domain`) — corroborate a signal already
  raised from local behavior; they never create one on their own (`system.md`'s
  evidence rules, enforced structurally by `adjudicate.py`).
- **The device directory** (`devices.py`) — a per-run inventory summarized into the
  bundle and queryable on demand (`get_device_directory`), not a detector.
- **The agent notebook** — persistent cross-run notes the model reads and can write
  (`add_notebook_entry`), never a signal source.
- **Canary results** — synthetic, injected events that prove detection is still
  working; reported separately in the run's self-test section, not as a `Finding`.

See [analyzers.md](analyzers.md) for how to add a new signal, and `docs/ARCHITECTURE.md`
§9 for the guardrails that govern what happens to one after it's raised.
