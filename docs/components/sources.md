# Sources

A source fetches raw records from one telemetry system and normalizes them into the
common `Event` model. That's the whole job: it does not analyze, and it does not decide
whether it's healthy - it reports facts and, when asked, runs a differential probe to
help the framework tell "your query was malformed" apart from "the feed is dead."

Two sources ship today: `librenms_syslog.py` (firewall/router syslog) and
`pihole_dns.py` (DNS queries). Both are read below in full, because the fastest way to
write a correct third source is to see two correct ones first.

## The contract

```python
# dawnpatrol/sources/base.py
class Source(ABC):
    name: str                              # unique; becomes Event.source
    kinds: frozenset[EventKind]             # kinds this source can emit
    requires_env: frozenset[str]            # gates auto-enablement
    max_window_hours: int | None = None     # retention ceiling, if any
    min_expected_records: int = 0           # volume floor for verify.py's sanity check

    def configure(self, profile: Profile) -> None: ...

    @abstractmethod
    def collect(self, window: Window, ctx: RunContext) -> CollectionResult: ...

    def self_test(self, ctx: RunContext) -> list[Probe]:
        return []   # override if you can cheaply prove empty != dead

    def effective_window(self, window: Window) -> Window:
        return window.clamp_hours(self.max_window_hours)   # rarely need to override

    def assign_zones(self, **kwargs) -> dict:
        ...   # helper: resolves src_zone/dst_zone from the profile for you
```

`CollectionResult` carries `events`, `reported_total`, `pages`, and `errors`.
`verify.py` applies generic gates on top of it (unique count ≈ `reported_total`, span ≈
requested window, non-zero) and calls your `extra_health_notes()` for anything
source-specific.

**`collect()` must not raise for zero results.** Returning an empty `CollectionResult` is
a legitimate outcome; the framework calls `self_test()` automatically whenever collection
returns nothing, and that probe evidence - not an exception - is what tells the reader
whether zero means "quiet day" or "something's broken."

## Window handling

Declare `max_window_hours` if your upstream has a hard retention ceiling (Pi-hole's ~24h
in-memory query log, for example). The framework clamps the requested window to it and
labels the result as a known limit, not a shortfall - the report says "DNS coverage:
23.99h of a 24h window (retention limit)," never a bare, alarming "incomplete."

## Walkthrough: `librenms_syslog.py`

The hard-won knowledge here is entirely about one API's footguns, encoded so they can
never recur:

- **`from`/`to` must be `"YYYY-MM-DD HH:MM:SS"` strings, url-encoded.** Passing Unix
  epoch integers returns `HTTP 200` with `total: 0` - no error, no warning. It looks
  exactly like a device that stopped forwarding syslog.
- **`self_test()` runs a four-probe differential** (no-filter, a control device with the
  same window, a narrow last-hour window, an auth check) whenever the primary device
  returns zero rows, so "my request was malformed" and "the router stopped logging" are
  never conflated.
- **iptables lines get parsed by regex** into action/interface/addresses/ports/TTL, and
  numeric protocol codes (`2`, `1`, `6`, `17`) are normalized to names (IGMP, ICMP, TCP,
  UDP) so a protocol breakdown isn't fragmented by accident.
- **The action match tolerates a leading kernel uptime stamp.** Not every firmware puts
  `DROP`/`ACCEPT`/`REJECT` at the very start of the message - OpenWrt-based gateways were
  found in production prefixing it with `"[4081245.82] drop wan out: IN=..."`, lowercase
  and behind a bracketed uptime. Before `_ACTION_RE` allowed an optional `[...]` prefix,
  every one of that firmware's lines silently fell through to a bare `SYSTEM` event -
  correctly collected (it shows up in the per-device record count) but invisible to every
  firewall-shaped analyzer, indistinguishable from DHCP chatter. If a device's firewall
  traffic seems to be missing from analysis despite `SourceHealth` showing records for it,
  check `kind` on its events before assuming a collection problem - this is a
  classification trap, not a collection one, and it can recur with a firmware this hasn't
  been tested against yet.
- **Non-KERNEL lines become `SYSTEM` or `AUTH` events** rather than being discarded. VPN
  daemon lines (`VPNSERVER*`/`OPENVPN`/`SSHD`/`PPTPD`) become `AUTH` - though in
  production this has turned out to be daemon lifecycle noise (startup, TUN/TAP
  up/down, `SIGTERM`) only, never a per-session "peer authenticated" line; see
  `analyzers/auth_activity.py` for what that means for VPN-specific analysis today.
  `WLCEVENTD`/`HOSTAPD` deauthentication lines *do* carry real device-authentication
  evidence - a client MAC and a reason - and become `AUTH` too, with the MAC in
  `Event.user`.
- **`DNSMASQ-DHCP` lease lines are parsed for device identity.** Confirmed against
  the real feed on all three devices (main router and both OpenWRT segment gateways)
  before being encoded: `DHCPACK(iface) ip mac [hostname]` is the authoritative lease
  grant, and the only verb that ever carries a hostname (only when the client sent
  one). `_parse_dhcp()` recognizes every DHCP verb (`DISCOVER`/`OFFER`/`REQUEST`/
  `ACK`/`RELEASE`/`INFORM`) and ignores dnsmasq's considerable non-lease chatter under
  the same program tag (domain-suffix noise, rebind-attack warnings, and - on the real
  IoT/DMZ gateways - "no address range available for DHCP request" pool-exhaustion
  errors at a genuinely notable ~2,000/day *each*, worth investigating in its own
  right) - these stay generic `SYSTEM` events, unchanged. A parsed line still
  becomes `SYSTEM` (not a new kind), with `action` set to the lowercased verb and the
  MAC in `Event.user` - the same field Wi-Fi deauthentication uses, so both feed
  `EntityType.DEVICE` novelty tracking (`analyzers/novel_clients.py`) identically. Only
  `DHCPACK` feeds the device directory (`devices.py`, role `dhcp-client`) with a real
  hostname and MAC - exactly what IoT/DMZ devices otherwise have neither SNMP
  inventory nor a local DNS resolver to be identified by any other way.
- **Device selection defaults to every device, auto-discovered fresh each run.**
  `DAWNPATROL_SOURCE_LIBRENMS_DEVICES` pins an explicit list when you want to exclude
  something; unset, `_device_directory()` calls `/devices` (one unpaginated call - unlike
  the syslog endpoint, LibreNMS returns its whole device list in one response) and
  collects from every id it reports. A directory-fetch failure only costs the
  hostname/hardware/OS enrichment described below, never the run: collection still
  proceeds from an explicit list if one is set, or is reported as a clear "nothing
  configured and nothing discovered" error if not.
- **Per-device collection outcome is one summary note, not one note per device.**
  Early on this listed every device on its own line in `SourceHealth.notes` - which
  every renderer's `notes[:5-6]` truncation then silently capped, hiding most devices
  in an actual deployment with more than a handful. Now it's a single line covering
  every device's record count (`"N device(s) collected from, records per device: h1=120,
  h2=45, ..."`), plus a second line naming any device that returned zero records - so
  the full picture survives the same render-time cap that used to hide it.
- **Every device with a private IP is registered in the cross-source device directory**
  (`dawnpatrol/devices.py`, `ARCHITECTURE.md` §8.3) - a per-run registry keyed by IP
  address, not by LibreNMS's own `device_id`, so any other source can contribute to the
  same entry. Public (globally routable) IPs are excluded by default - a personal
  domain monitored over ping is a real example that showed up in this device list -
  set `DAWNPATROL_DEVICES_INCLUDE_PUBLIC_IPS=true` to include those too. That directory reaches both the internal stage-7 investigation agent
  (a summary every run, full detail through its own `get_device_directory` tool) and, via
  the finished report, an external MCP agent through the identically-named
  `get_device_directory` MCP tool (`docs/components/mcp-server.md`) - deliberately the
  *only* device-related MCP tool: no LibreNMS-specific tool exists, so the surface stays
  core functionality rather than growing one bespoke tool per plugin.

## Walkthrough: `pihole_dns.py`

Three behaviors of the Pi-hole v6 API caused real, silent data loss before they were
encoded here:

- **`cursor` pagination can be a no-op** on some builds - it returns the identical page
  with an identical cursor forever, so a naive loop terminates after two passes having
  written one page of real data twice. `start` (offset) is the parameter that actually
  works, and the integrity gate (unique record count vs. `recordsFiltered`) catches
  duplication regardless of which one you used.
- **The query log contains malformed mDNS names with raw non-UTF-8 bytes.** A strict
  `.decode()` raises mid-pull and silently truncates everything collected before the
  crash from ever being analyzed. Every decode here uses `errors="replace"`.
- **Loop on `recordsFiltered` (matches your window), never `recordsTotal`** (the whole
  on-disk database) - the difference between them was 16x on a real pull.

`max_window_hours` defaults to 24 (FTL's typical in-memory retention) and is itself
overridable via `DAWNPATROL_SOURCE_PIHOLE_MAX_WINDOW_HOURS` for a deployment that retains
more.

- **Every distinct client IP also feeds the cross-source device directory**, tagged with
  a `dns-client` role and a name if Pi-hole resolved one. Pi-hole never reports
  hardware or OS - only a client IP, occasionally with a name - but that is still a
  real contribution: it is the only source that ever sees some client-only devices (a
  phone, a smart plug) that never appear in LibreNMS's own managed-device list at all.
- **`block_reason` carries the raw resolution status for every query, not only blocked
  ones.** It used to be populated only when `blocked=True` (`GRAVITY`/`DENYLIST`/etc.);
  it is now always set to Pi-hole's own status string - `NXDOMAIN`/`FORWARDED`/`CACHE`/
  etc. for everything else. `blocked` remains the sole authority on whether a query was
  actually blocked; `block_reason` on an unblocked query is what
  `dns_anomalies.py`'s NXDOMAIN-rate-outlier check reads to spot a client resolving far
  more nonexistent domains than its peers - a DGA-shaped pattern the block rate alone
  cannot see, since a nonexistent domain is never something Pi-hole blocks.

## Build your own

Copy `dawnpatrol/sources/TEMPLATE.py` (skipped by the plugin registry, so it's a safe
starting point, never accidentally loaded) to a new file and work through its checklist:

1. **Pick a `name`.** It becomes both `Event.source` and the environment-variable prefix
   convention (`DAWNPATROL_SOURCE_<NAME>_*`).
2. **Declare `requires_env`.** The source auto-enables the moment every variable in the
   set is present - no registry file to edit.
3. **Set `max_window_hours`** if the upstream has a retention ceiling.
4. **Normalize into `Event`.** Use `self.assign_zones(src_ip=..., dst_ip=...)` to resolve
   `src_zone`/`dst_zone` from the profile automatically - this is what lets an analyzer
   later say "IoT segment reached an unexpected destination" without a single hardcoded
   CIDR in your source file.
5. **Write `self_test()`** if you can cheaply distinguish "empty and that's correct" from
   "empty and something's wrong" - an unfiltered probe, a narrower time window, an auth
   check against a known-good endpoint.
6. **Contribute to the device directory if you know anything device-shaped.** Call
   `ctx.devices.update(ip, source=self.name, role="...", hostname=..., ...)` from inside
   `collect()` for any IP you can identify - even just a bare IP with no other field
   filled in is a legitimate contribution. See `dawnpatrol/devices.py` and the LibreNMS/
   Pi-hole walkthroughs above for what "partial" looks like in practice.

A realistic example: adding a NetFlow/IPFIX source. `EventKind.FLOW` is already reserved
for exactly this. Your `collect()` would map flow records into `Event(kind=FLOW, src_ip=,
dst_ip=, dst_port=, proto=, pkt_len=, ...)`; every existing analyzer that reads firewall-
shaped fields (`analyzers/firewall_patterns.py`'s prober/sweep classification, for
instance) becomes usable against flow data with zero changes, because both kinds share
the same `Event` fields.

### Wire it up and test it

```bash
# No API spend - see exactly what your source produced and how it was classified.
DAWNPATROL_SOURCE_MYTHING_URL=http://... dawnpatrol run --stop-after analyze
dawnpatrol probe          # runs self_test() against the live system
dawnpatrol list-plugins   # confirms it auto-enabled, or tells you what's still missing
```

Add tests in `tests/test_sources.py` following the existing pattern: synthetic raw
records constructed inline (not files in `tests/fixtures/` - see `docs/ARCHITECTURE.md`
§14 for why), one test per parsing trap you know about, and one asserting the
integrity/sanity checks actually catch a truncated or duplicated pull.
