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

## Collecting query data

`GET /api/queries` is the only source of DNS query/block data on this instance.
Use the script below verbatim. Two non-obvious properties of this instance are baked
into it, and both have caused silent, confident data loss in production runs:

### 1. Paginate with `start`, never with `cursor`

**`cursor` is a no-op here.** It returns the identical page with an identical cursor
value forever. A loop that breaks on `new_cursor == cursor` therefore terminates after
two passes having collected one page of real data, written twice — 20,000 lines
containing 10,000 unique IDs. It reports success.

Verified:
```
page1                  → 10000 records, cursor=51413379, range 00:48–01:36
page2 (cursor=…379)    → 10000 records, cursor=51413379, SAME ids, SAME range
page3 (cursor=…379)    → cursor unchanged again
```

**`start` is the working parameter.** It returns non-overlapping pages walking backward
in time, at constant speed regardless of depth:
```
start=0       n=10000  0.3s   2026-08-10 09:19:22..10:38:10
start=50000   n=10000  0.3s   2026-08-10 03:20:45..04:23:10
start=100000  n=10000  0.3s   2026-08-09 22:43:30..23:38:25
start=200000  n=10000  0.4s   2026-08-09 12:19:54..13:46:16
```
There is no depth-related slowdown and no timeout. **If a page fails, the cause is not
offset depth** — see the decoding note below before concluding the method is broken.

If you find yourself with exactly 20,000 records, you used `cursor`. Re-collect.

### 2. Decode with `errors="replace"` — a poison record will kill the loop

The query log contains malformed mDNS domains with raw non-UTF-8 bytes. A strict
`.decode()` raises `UnicodeDecodeError` mid-pull and aborts everything collected after
that point. Verified:
```
CRASHED on page 14 (offset 130000) after 130000 records
'utf-8' codec can't decode byte 0xc0 in position 816122: invalid start byte
b'..."domain":"lb._dns-sd._udp.\xc0\x01\x02","upstream":null...'
```
Three such records exist, all from client `10.0.10.211` (a device emitting
compressed/truncated DNS-SD names). They are a client-side quirk, **not** a security
finding and not worth reporting as one.

Always decode with `errors="replace"`. Never let this exception be interpreted as
"pagination is broken" — that misdiagnosis is what caused a run to abandon offset
pagination and fall back to a 20,000-record cursor result.

### 3. Loop against `recordsFiltered`, not `recordsTotal`

- `recordsFiltered` — records matching your `from`/`until`. **This is the loop target.**
- `recordsTotal` — records in the whole database, ignoring your window.

With a 1h window: `recordsFiltered=11897` vs `recordsTotal=195366`. Looping on the
wrong one sends you 16x too far or stops you far too early.

### 4. Retention is ~24h — a 48h DNS window is impossible

`/api/queries` is served from FTL's in-memory log, which holds ~24h here. Requesting
48h or 96h returns the same ~24h. The on-disk DB (`earliest_timestamp_disk`) goes back
months but is **not** reachable through this endpoint.

Read `earliest_timestamp` from the first response and treat
`max(requested_from, earliest_timestamp)` as your true window start. Report achieved
coverage in hours. Label the shortfall a **known retention limit**, not a collection
failure and not a security finding. Never extrapolate 24h counts to a 48h figure.

### The collection script

Save to a file and run with `python3`. A full ~24h pull is **23 pages / ~222,000
records in ~9 seconds**.

```python
#!/usr/bin/env python3
"""
query_pihole.py — authenticated, offset-paginated, decode-tolerant Pi-hole v6 pull.

Usage:
    python3 query_pihole.py [hours_back] [output_path]

Exits non-zero if the pull fails its integrity checks. Never reports success
on a partial or duplicated result.
"""

import json, sys, time, ssl, urllib.request, datetime

PIHOLE_HOST   = "10.0.10.69"
PIHOLE_SCHEME = "http"
API_PASSWORD  = "*****REDACTED-PIHOLE-API-PASSWORD*****"     # FTLCONF_webserver_api_password
PAGE_SIZE     = 10000            # hard server-side cap
MAX_RETRIES   = 3

BASE_URL = f"{PIHOLE_SCHEME}://{PIHOLE_HOST}/api"

BLOCKED_STATUSES = {
    "GRAVITY", "GRAVITY_CNAME", "DENYLIST", "DENYLIST_CNAME",
    "REGEX", "REGEX_CNAME", "SPECIAL_DOMAIN", "EXTERNAL_BLOCKED_IP",
    "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
}

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _request(method, path, headers=None, body=None, timeout=120):
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        # errors="replace" is REQUIRED. Raw 0xc0 bytes appear in malformed
        # mDNS domains; strict decoding aborts the pull at ~page 14.
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def authenticate():
    resp = _request("POST", "/auth", body={"password": API_PASSWORD})
    sid = resp.get("session", {}).get("sid")
    if not sid:
        raise RuntimeError(f"Authentication failed: {resp}")
    return sid


def logout(sid):
    try:
        _request("DELETE", "/auth", headers={"sid": sid})
    except Exception:
        pass  # best-effort; DELETE /auth may return a non-JSON body


def fetch_queries(sid, hours_back=24):
    """Offset-paginated pull. Returns (records, recordsFiltered, from_ts, now, complete)."""
    H = {"sid": sid}
    now = int(time.time())
    from_ts = now - hours_back * 3600

    probe = _request("GET", f"/queries?from={from_ts}&until={now}&length=1", headers=H)
    total = probe.get("recordsFiltered", 0)          # NOT recordsTotal
    earliest = probe.get("earliest_timestamp")

    if earliest and float(earliest) > from_ts:
        avail = (now - float(earliest)) / 3600
        print(f"[!] RETENTION LIMIT: requested {hours_back}h, only {avail:.2f}h "
              f"retained. This is expected, not a failure.", file=sys.stderr)

    seen, offset, pages, fails = {}, 0, 0, 0
    while offset < total:
        try:
            resp = _request(
                "GET",
                f"/queries?from={from_ts}&until={now}"
                f"&length={PAGE_SIZE}&start={offset}",
                headers=H,
            )
        except Exception as e:
            fails += 1
            print(f"[!] page at offset {offset} failed ({e!r}), "
                  f"retry {fails}/{MAX_RETRIES}", file=sys.stderr)
            if fails >= MAX_RETRIES:
                print(f"[!] ABANDONED at offset {offset} of {total}", file=sys.stderr)
                return list(seen.values()), total, from_ts, now, False
            time.sleep(2)
            continue          # retry SAME offset — do not skip records
        fails = 0

        batch = resp.get("queries", [])
        pages += 1
        if not batch:
            break
        for q in batch:
            seen[q["id"]] = q          # dedupe by id
        offset += len(batch)

    print(f"[+] {pages} pages, {len(seen)} unique records", file=sys.stderr)
    return list(seen.values()), total, from_ts, now, True


def main():
    hours_back = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    sid = authenticate()
    try:
        queries, total, from_ts, now, complete = fetch_queries(sid, hours_back)
    finally:
        logout(sid)

    # ---------- BLOCKING INTEGRITY CHECKS ----------
    if not queries:
        sys.exit("[!] FATAL: zero records returned — do not report success.")

    ids = [q["id"] for q in queries]
    if len(ids) != len(set(ids)):
        sys.exit(f"[!] FATAL: {len(ids)} records, {len(set(ids))} unique — "
                 f"duplicated pages. You are using cursor pagination.")

    if abs(len(queries) - total) > max(50, 0.01 * total):
        sys.exit(f"[!] FATAL: {len(queries)} unique vs recordsFiltered={total} "
                 f"— pull is incomplete. Do not analyze this data.")

    if not complete:
        sys.exit("[!] FATAL: pagination abandoned before completion.")

    ts = [q["time"] for q in queries]
    span_h = (max(ts) - min(ts)) / 3600
    U = datetime.UTC
    f = lambda t: datetime.datetime.fromtimestamp(float(t), U).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[+] span {f(min(ts))} -> {f(max(ts))} = {span_h:.2f}h "
          f"(requested {hours_back}h)", file=sys.stderr)
    print(f"[+] ACHIEVED COVERAGE: {span_h:.2f}h — report this figure verbatim.",
          file=sys.stderr)

    blocked = sum(1 for q in queries if q.get("status") in BLOCKED_STATUSES)
    print(f"[+] blocked={blocked} rate={100*blocked/len(queries):.1f}%", file=sys.stderr)

    out = open(out_path, "w") if out_path else sys.stdout
    try:
        for q in queries:
            out.write(json.dumps(q) + "\n")
    finally:
        if out_path:
            out.close()


if __name__ == "__main__":
    main()
```

### Verifying the pull before you analyze (blocking)

The script exits non-zero on any of these. If you collect by other means, check them
yourself — each corresponds to a real failure observed on this instance:

| Check | Failure it catches |
|---|---|
| unique ID count == record count | cursor duplication (20,000 lines / 10,000 IDs) |
| unique count ≈ `recordsFiltered` (±1%) | truncated pull, poison-record abort |
| non-zero records | empty result reported as success |
| pagination ran to completion | abandoned loop reported as complete |
| timestamp span computed in hours | ~1.4h sample reported as a 48h window |

Report achieved coverage in hours in every output. **"Full pagination, all statuses" is
a claim, not a verification** — that exact phrase has accompanied both a 53-minute
sample and a duplicated page.

### Expected healthy result (~24h window, this instance)

```
23 pages · 222,245 unique records · ~9s · unique == recordsFiltered
span 23.99h
CACHE 79,075 · CACHE_STALE 63,984 · GRAVITY 59,398 · FORWARDED 11,479 ·
SPECIAL_DOMAIN 4,050 · IN_PROGRESS 3,828 · RETRIED 301 · GRAVITY_CNAME 130
block rate 28.6%
```

If your numbers are an order of magnitude below this, the pull failed — regardless of
what the collection step reported.

### Status values

**Blocked** (count all toward the block rate):
`GRAVITY`, `GRAVITY_CNAME`, `DENYLIST`, `DENYLIST_CNAME`, `REGEX`, `REGEX_CNAME`,
`SPECIAL_DOMAIN`, `EXTERNAL_BLOCKED_IP`, `EXTERNAL_BLOCKED_NULL`, `EXTERNAL_BLOCKED_NXRA`

**Allowed:** `FORWARDED`, `CACHE`, `CACHE_STALE`, `RETRIED`, `RETRIED_DNSSEC`
**Transient:** `IN_PROGRESS` — exclude from block-rate denominators or note its inclusion.

Filtering only for `GRAVITY` understates the block rate materially: `SPECIAL_DOMAIN`
(4,050) and `GRAVITY_CNAME` (130) are real blocks on this instance.

### Cheaper alternatives for top-N

`GET /api/stats/summary`, `/api/stats/top_domains`, `/api/stats/top_clients` are
pre-aggregated, are not subject to the 10,000-row page cap, and need no pagination.
Prefer them when you need top-N rather than raw per-query records.
