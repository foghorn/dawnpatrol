# Network profile

`profile.yml` is the one file that turns DawnPatrol from a generic pipeline into an
analyst that knows *your* network. It's the reason the source tree is publishable at
all: every address, segment, device role, and local quirk lives here, gitignored, mounted
read-only into the container - never in code.

It's also more than documentation for a human reader. Every field below has a direct,
mechanical effect on analysis - the profile is data the analyzers and the model both
read, not a comment.

## The file (`dawnpatrol/profile.py`)

```yaml
site: { name: "home", timezone: "UTC" }

zones:
  - name: iot
    cidrs: ["192.168.50.0/24"]
    trust: untrusted
    gateway: "192.168.1.8"
    notes: >
      Cameras and home automation. Unpatchable and chatty. Expected behaviour
      is a small, stable set of vendor cloud endpoints plus NTP.
    expected_egress_domains: ["*.vendor-cloud.example", "*.pool.ntp.org"]

hosts:
  - { ip: "192.168.1.53", name: pihole, role: dns-resolver, authoritative_resolver: true }

policy:
  wan_ip_is_dynamic: true
  approved_resolvers: ["192.168.1.53"]
  attack_surface_ports: [22, 23, 80, 443, 3389, ...]
  nat_attribution_limited_behind: ["192.168.1.8"]
  # benign_domain_suffixes: [google.com, ...]   # omit to use the built-in list

known_quirks:
  - "Some consumer router firmware mislabels routine chatter as 'emerg' severity."
```

## What each field actually does

| Field | Mechanical effect |
|---|---|
| `zones[].cidrs` | `Profile.zone_of(ip)` resolves any address to a zone name at normalize time (`Source.assign_zones`), or to the synthetic `"private"`/`"external"` otherwise. Every `src_zone`/`dst_zone` on every `Event` traces back to this. |
| `zones[].gateway` | Combined with `policy.nat_attribution_limited_behind` (see below) to generate the "traffic is NATed, per-device attribution isn't possible" caveat automatically, on any finding whose subject is that gateway. |
| `zones[].expected_egress_domains` | `segment_review.py`'s unexpected-egress check: DNS resolution from that zone to anything not matching this list becomes a signal. An empty list makes every destination "unexpected," which is noisy - fill this in before relying on that analyzer. |
| `policy.approved_resolvers` | Any internal host resolving DNS elsewhere is a policy violation - a HIGH-severity signal, not a preference. |
| `policy.attack_surface_ports` | `firewall_patterns.py` raises a persistent prober's severity from LOW to MEDIUM when its target port is in this list. |
| `policy.nat_attribution_limited_behind` | `Profile.attribution_caveat(ip)` - the renderer emits "originating from behind the gateway; per-device attribution is not possible" automatically for any finding whose subject is one of these addresses, instead of the model needing to remember to say so. **Only list a gateway here if its own logs genuinely cannot reveal the originating client** - not every NAT gateway qualifies. A real deployment found the opposite: two OpenWrt gateways NAT their egress traffic, but their own forwarded firewall/kernel logs still carry the real pre-NAT client IP in `SRC=`/`DST=`, so per-device attribution was actually available and listing them here was simply wrong. Check a gateway's own forwarded log format before adding it, and remove it if that log turns out to carry real client addresses after all. |
| `policy.benign_domain_suffixes` | `Profile.is_benign_domain()` - gates both enrichment budget (never spend a lookup on a known-good domain) and novelty detection (a subdomain of a benign suffix is never "newly seen" in a way that matters). Omit the key entirely to use the built-in list of major cloud/CDN providers. |
| `known_quirks` | Injected verbatim into the cached prompt block (`as_context()`). This is where you record "this router mislabels X as emerg severity" once, instead of it being rediscovered as a false finding every few weeks. |

## `as_context()`: the text the model actually sees

`Profile.as_context()` renders the whole profile as one deterministic text block,
injected into the harness's cached system-prompt segment (`agent/harness.py`) - and
that's also exactly what the MCP server's `get_network_profile` tool returns (see
`docs/components/mcp-server.md`). **Deterministic** is load-bearing: no timestamps, no
counts, nothing that varies between runs, because this block sits before the prompt
cache breakpoint (§6.2 of `docs/ARCHITECTURE.md`) and anything volatile there silently
defeats caching for the entire run.

## Zone resolution, precisely

`zone_of(ip)` checks configured zones first (first CIDR match wins), then falls back to
`"private"` for RFC1918/loopback/link-local space not covered by any zone, then
`"external"` for anything else - including, deliberately, the RFC 5737 documentation
ranges the canary system uses. `is_external()` and `is_routable()` are *not* the same
check: `is_external()` is broader (an address can be "external" and still not globally
routable), and using the wrong one has a real cost - `is_routable()` is what gates an
enrichment lookup, and submitting a non-routable address wastes budget a real candidate
needed.

## Build your own: documenting a new segment

Adding a segment - a guest Wi-Fi VLAN, a new IoT subnet - is a YAML edit, not a code
change:

```yaml
zones:
  - name: guest
    cidrs: ["192.168.60.0/24"]
    trust: untrusted
    notes: >
      Guest Wi-Fi. No expected server-side traffic; anything inbound to this
      segment is notable on its own.
    expected_egress_domains: ["*.captive-portal.example"]
```

Every analyzer, the segment-review report section, and the MCP server's
`get_network_profile` tool pick this up on the next run with zero code touched. The one
thing worth doing deliberately: **fill in `expected_egress_domains` before you rely on
unexpected-egress detection for a segment.** An empty list there is indistinguishable
from "everything is unexpected," which is exactly what happened during initial rollout
of the reference deployment's IoT zone - a TODO left in the list until real vendor
domains were captured and added.

### Wire it up and test it

```bash
dawnpatrol validate                    # confirms the profile parses and lists zone count
dawnpatrol run --stop-after analyze    # segment_review's output shows immediately, free
```

`tests/conftest.py` has a small representative `PROFILE_YAML` fixture used across the
suite - copy its shape for a test profile rather than pointing tests at your real,
gitignored one.
