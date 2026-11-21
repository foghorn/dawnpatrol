"""Web server access logs: who is attacking the sites, and did anything work.

Reads ``EventKind.HTTP`` events (``sources/ssh_host.py``: ``src_ip`` client,
``domain`` site, ``program`` method, ``action`` status, ``pkt_len`` bytes,
``raw.path`` the requested URL). Any public site is scanned all day, so the
checks separate background noise (rated LOW) from the few shapes that mean
something reached the application:

* scanning: clients probing many paths, or the classic sensitive ones
  (``/.env``, ``/.git/``, admin panels...) - one LOW summary for all of them,
  plus a HIGH per client when a sensitive probe got a 2xx (the file is
  actually exposed)
* injection attempts in the URL (traversal, SQL, template/JNDI, shell) - one
  LOW summary for the refused ones, MEDIUM per client when one got a 2xx or
  5xx (it reached code that ran, or broke)
* web-shell shape: a script inside an uploads/static folder answering 2xx
  (HIGH), or a POST to one (also HIGH)
* login brute force: many POSTs to login paths from one client
* server-error spikes per site
* large responses to one client (possible data leaving)
* WordPress login attacks: a site-wide spray (many clients, few attempts
  each - invisible to a per-client count), xmlrpc.php abuse, and a successful
  login (POST /wp-login.php answered 302) from an address outside
  DAWNPATROL_WEB_TRUSTED_CLIENTS - MEDIUM, HIGH when that client also failed
  first or the site was being sprayed
* disguised clients: a Googlebot/Bingbot user agent from outside the ranges
  those crawlers publish (``crawlers.py``), and one client rotating many user
  agents - one LOW summary each
* new script endpoints: a .php/.jsp/... path that ran (2xx, or an accepted
  POST) and never had before, per the long-term baseline - MEDIUM, HIGH when
  it accepted a POST. Silent on the first run that records web history.
* admin pages answered 2xx (static assets excluded), one LOW summary listing
  the clients, for the model to judge against the profile's known admin
  addresses and monitors

Noise is summarized, not itemized: a public shared host draws hundreds of
scanners a day, and one signal per scanner would crowd the rest of the
network out of the model's evidence. Per-client signals are kept for the
shapes that mean something reached the application.

Thresholds are module constants. A crawler or monitor that trips one belongs in
the profile (host notes or known_quirks), not in a raised threshold.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any

from .. import crawlers
from ..models import AnalyzerResult, Entity, EntityType, EventKind, Metric, Severity, Signal
from ..profile import Profile
from ..query import EventQuery
from ..secrets import read_list
from ..store import script_endpoint
from .base import Analyzer
from .baseline import Baseline

SCAN_404_MIN = 30
SCAN_SENSITIVE_MIN = 3
LOGIN_POST_MIN = 20
LOGIN_SPRAY_ATTEMPTS = 30
LOGIN_SPRAY_CLIENTS = 10
LOGIN_FAILS_BEFORE = 3
UA_ROTATION_MIN = 10
NEW_SCRIPTS_LISTED = 20
ERROR_5XX_MIN = 20
ERROR_5XX_SHARE = 0.05
LARGE_RESPONSE_BYTES = 200 * 1024 * 1024
LARGE_CLIENT_BYTES = 1024 * 1024 * 1024
_LIST = 10
_ROWS = 200_000

SENSITIVE = re.compile(
    r"/\.env\b|/\.git/|/\.aws/|/\.ssh/|/\.svn/|/\.DS_Store|/wp-config\.php|/config\.(php|json|ya?ml)\b"
    r"|/phpmyadmin|/pma/|/adminer|/server-status|/actuator\b|/vendor/phpunit|/boaform"
    r"|/HNAP1|/cgi-bin/|/\.well-known/security\.txt-|/debug/|/console\b|/_profiler"
    r"|/backup\.(zip|tar|sql)|\.sql(\.gz)?$|/db\.sql|/dump\.sql", re.I)
INJECTION = re.compile(
    r"\.\./|%2e%2e|/etc/passwd|win\.ini|union(\s|%20|\+)+select|sleep\(\d|"
    r"\$\{jndi:|%24%7bjndi|\{\{.*\}\}|<script|%3cscript|;\s*(wget|curl|sh|bash)\b|"
    r"\|\s*(sh|bash)\b|cmd=|exec\(|base64_decode|php://|file://|/proc/self/", re.I)
UPLOAD_SCRIPT = re.compile(
    r"/(uploads?|files|images?|img|media|static|assets|tmp|temp|cache|wp-content/uploads)/"
    r"[^?]*\.(php\d?|phtml|jsp|jspx|aspx?|ashx|cgi|pl|py|sh)(\?|$)", re.I)
LOGIN = re.compile(r"login|signin|sign-in|/auth\b|/session|wp-login\.php|xmlrpc\.php|"
                   r"/user/password|/admin/?$", re.I)
WP_LOGIN = re.compile(r"/wp-login\.php(\?(?!.*\baction=(?!login\b))|$)", re.I)
XMLRPC = re.compile(r"/xmlrpc\.php(\?|$)", re.I)
ADMIN = re.compile(r"^/(wp-admin(?!/admin-ajax)|admin|administrator|manager/html|phpmyadmin|"
                   r"adminer|_admin|dashboard|cpanel)(/|$|\?)", re.I)
STATIC = re.compile(r"\.(css|js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot)(\?|$)", re.I)


class HttpActivityAnalyzer(Analyzer):
    name = "http_activity"
    requires_kinds = frozenset({EventKind.HTTP})
    order = 50

    def run(self, q: EventQuery, profile: Profile, baseline: Baseline) -> AnalyzerResult:
        r = AnalyzerResult(analyzer=self.name)
        rows = q.detail_rows(kind=EventKind.HTTP, limit=_ROWS)
        if not rows:
            return r
        if len(rows) >= _ROWS:
            r.notes.append(f"http_activity read the first {_ROWS} requests only; checks on "
                           f"the rest of the window were skipped")
        for row in rows:
            row["path"] = row["raw"].get("path") or ""
            row["status"] = _int(row["action"])

        statuses = Counter(x["status"] // 100 for x in rows if x["status"])
        sites = Counter(x["domain"] or "?" for x in rows)
        r.metrics += [
            Metric(key="http.requests", value=len(rows), section="web", label="HTTP requests"),
            Metric(key="http.clients", value=len({x["src_ip"] for x in rows}), section="web",
                   label="Distinct HTTP clients"),
            Metric(key="http.sites", value=len(sites), section="web", label="Sites with traffic"),
            Metric(key="http.4xx", value=statuses.get(4, 0), section="web",
                   label="HTTP 4xx responses"),
            Metric(key="http.5xx", value=statuses.get(5, 0), section="web",
                   label="HTTP 5xx responses"),
        ]
        for site, n in sites.most_common(8):
            r.metrics.append(Metric(key=f"http.site.{site}", value=n, section="web",
                                    label=f"{site}: requests"))

        # A site's own server calling itself (WordPress cron, Jetpack sync) is
        # not a client: leave it out of the per-client checks.
        by_client: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            if row["src_ip"] and row["src_ip"] == row.get("dst_ip"):
                continue
            by_client[row["src_ip"] or "?"].append(row)

        self._wordpress_logins(r, rows)
        self._disguised(r, by_client)
        self._new_scripts(r, rows, baseline)
        self._scanning(r, by_client)
        self._injection(r, by_client)
        self._webshell(r, rows)
        self._login(r, by_client)
        self._errors(r, rows)
        self._large(r, rows, by_client)
        self._admin(r, rows)
        return r

    # ----- checks ----------------------------------------------------------- #

    def _scanning(self, r: AnalyzerResult, by_client: dict[str, list[dict]]) -> None:
        scanners: dict[str, list[dict]] = {}
        for client, items in by_client.items():
            sensitive = [i for i in items if SENSITIVE.search(i["path"])]
            exposed = [i for i in sensitive if 200 <= i["status"] < 300]
            not_found = sum(1 for i in items if i["status"] == 404)
            if exposed:
                r.signals.append(self._signal(
                    f"web.exposed_sensitive_path.{client}",
                    f"Sensitive path answered 2xx to {client}", "web.sensitive_exposure",
                    Severity.HIGH, 0.75, exposed,
                    "A path scanners look for (an .env file, a .git folder, a config or "
                    "backup, an admin tool) returned success. Check what the response "
                    "contained: if it was real configuration or source, treat its secrets "
                    "as leaked and rotate them."))
            # Probing, not volume: crawlers fetch thousands of distinct pages
            # without a single 404 or sensitive probe.
            elif len({i["path"] for i in sensitive}) >= SCAN_SENSITIVE_MIN \
                    or not_found >= SCAN_404_MIN:
                scanners[client] = items
        if not scanners:
            return
        def probing(items: list[dict]) -> tuple[int, int]:
            return (len({i["path"] for i in items if SENSITIVE.search(i["path"])}),
                    sum(1 for i in items if i["status"] == 404))

        ranked = sorted(scanners.items(), key=lambda kv: tuple(-n for n in probing(kv[1])))
        everything = [i for _c, items in ranked for i in items]
        everything.sort(key=lambda i: i["ts"])
        probed = Counter(i["path"].split("?", 1)[0] for i in everything
                         if SENSITIVE.search(i["path"]))
        r.signals.append(self._signal(
            "web.scanners", f"{len(scanners)} clients scanned the sites", "web.scanner",
            Severity.LOW, 0.6, everything,
            "Every public site is scanned constantly; this is the day's background. It "
            "matters only through the separate signals for anything a scan actually "
            "reached (a sensitive path answered 2xx, injection that got 2xx/5xx, a "
            "script answering from an upload folder). Query the events table for any "
            "client listed here.",
            extra={"scanning_clients": len(scanners),
                   "top_scanners": [{"client": c, "requests": len(items),
                                     "sensitive_probes": probing(items)[0],
                                     "not_found": probing(items)[1],
                                     "sites": sorted({i["domain"] for i in items
                                                      if i.get("domain")})[:5]}
                                    for c, items in ranked[:_LIST]],
                   "most_probed_paths": dict(probed.most_common(_LIST))}))

    def _injection(self, r: AnalyzerResult, by_client: dict[str, list[dict]]) -> None:
        refused: dict[str, list[dict]] = {}
        for client, items in by_client.items():
            hits = [i for i in items if INJECTION.search(i["path"])]
            if not hits:
                continue
            landed = [i for i in hits if 200 <= i["status"] < 300 or i["status"] >= 500]
            if not landed:
                refused[client] = hits
                continue
            r.signals.append(self._signal(
                f"web.injection_attempt.{client}",
                f"Injection attempts from {client} - some got 2xx/5xx",
                "web.injection_attempt", Severity.MEDIUM, 0.6, hits,
                "URLs carrying path traversal, SQL, template/JNDI or shell syntax, and "
                "the application answered: a 2xx means it accepted the request, a 5xx "
                "that it broke on it. Check the application's own log for these "
                "requests.",
                extra={"reached_application": len(landed)}))
        if refused:
            everything = sorted((i for items in refused.values() for i in items),
                                key=lambda i: i["ts"])
            r.signals.append(self._signal(
                "web.injection_refused", f"Injection attempts from {len(refused)} client(s), "
                f"all refused", "web.injection_attempt", Severity.LOW, 0.6, everything,
                "Injection syntax in URLs, every one answered 4xx: background noise "
                "unless the same clients show up in a signal for something that "
                "reached the application.",
                extra={"clients_refused": len(refused)}))

    def _webshell(self, r: AnalyzerResult, rows: list[dict]) -> None:
        hits = [x for x in rows if UPLOAD_SCRIPT.search(x["path"])
                and (200 <= x["status"] < 300 or x["program"] == "POST")
                and x["status"] != 404]
        by_path: dict[str, list[dict]] = defaultdict(list)
        for x in hits:
            by_path[f"{x['domain']}{x['path'].split('?', 1)[0]}"].append(x)
        for path, items in by_path.items():
            r.signals.append(self._signal(
                f"web.webshell_shape.{path}"[:255],
                f"Script in an upload/static folder answered: {path}"[:200],
                "web.webshell", Severity.HIGH, 0.7, items,
                "A script file inside an uploads, files or static folder should not run. "
                "One that answers - especially to POSTs from a few addresses - is the "
                "classic web shell. Inspect the file on disk and how it got there."))

    def _login(self, r: AnalyzerResult, by_client: dict[str, list[dict]]) -> None:
        for client, items in by_client.items():
            posts = [i for i in items if i["program"] == "POST" and LOGIN.search(i["path"])]
            if len(posts) < LOGIN_POST_MIN:
                continue
            r.signals.append(self._signal(
                f"web.login_bruteforce.{client}",
                f"{len(posts)} login POSTs from {client}", "web.login_bruteforce",
                Severity.MEDIUM, 0.6, posts,
                "Many login attempts from one address. Check the application's own log "
                "for a success from it, and whether the targeted account exists."))

    def _errors(self, r: AnalyzerResult, rows: list[dict]) -> None:
        by_site: dict[str, list[dict]] = defaultdict(list)
        for x in rows:
            by_site[x["domain"] or "?"].append(x)
        for site, items in by_site.items():
            errors = [i for i in items if i["status"] >= 500]
            if len(errors) >= ERROR_5XX_MIN and len(errors) / len(items) >= ERROR_5XX_SHARE:
                r.signals.append(self._signal(
                    f"web.server_errors.{site}",
                    f"{site}: {len(errors)} server errors ({len(errors) / len(items):.0%})",
                    "web.server_errors", Severity.LOW, 0.5, errors,
                    "A burst of 5xx is usually a broken deploy or an overloaded backend, "
                    "occasionally an attack hitting a fragile endpoint. Check which paths "
                    "and clients the errors cluster on.",
                    extra={"site_requests": len(items)}))

    def _large(self, r: AnalyzerResult, rows: list[dict],
               by_client: dict[str, list[dict]]) -> None:
        for client, items in by_client.items():
            sent = sum(i["pkt_len"] or 0 for i in items if 200 <= i["status"] < 300)
            big = [i for i in items if (i["pkt_len"] or 0) >= LARGE_RESPONSE_BYTES]
            if sent < LARGE_CLIENT_BYTES and not big:
                continue
            r.signals.append(self._signal(
                f"web.large_transfer.{client}",
                f"{_mb(sent)} sent to {client}", "web.large_transfer", Severity.LOW, 0.5,
                big or items,
                "Large responses to one client: normal for downloads and media, notable "
                "for an API, a backup file or anything that should be small.",
                extra={"bytes_sent": sent, "largest_paths": sorted(
                    {i["path"][:200] for i in sorted(items, key=lambda x: -(x["pkt_len"] or 0))[:5]})}))

    def _wordpress_logins(self, r: AnalyzerResult, rows: list[dict]) -> None:
        trusted = _networks(read_list("DAWNPATROL_WEB_TRUSTED_CLIENTS"))
        attempts = [x for x in rows if x["program"] == "POST" and WP_LOGIN.search(x["path"])]
        xmlrpc = [x for x in rows if x["program"] == "POST" and XMLRPC.search(x["path"])]
        sprayed: set[str] = set()
        by_site: dict[str, list[dict]] = defaultdict(list)
        for x in attempts + xmlrpc:
            by_site[x["domain"] or "?"].append(x)
        for site, items in by_site.items():
            clients = Counter(i["src_ip"] for i in items)
            if len(items) < LOGIN_SPRAY_ATTEMPTS or len(clients) < LOGIN_SPRAY_CLIENTS:
                continue
            sprayed.add(site)
            items.sort(key=lambda i: i["ts"])
            r.signals.append(self._signal(
                f"web.login_spray.{site}",
                f"{site}: {len(items)} login attempts from {len(clients)} clients",
                "web.login_spray", Severity.LOW, 0.65, items,
                "A distributed password attack: many addresses, a few tries each, so "
                "no single client looks like brute force. It only matters if one "
                "succeeded (see any web.login_success signal) - and it is why "
                "exposed usernames (/wp-json/wp/v2/users, ?author=) are worth closing.",
                extra={"login_posts": sum(1 for i in items if XMLRPC.search(i["path"]) is None),
                       "xmlrpc_posts": sum(1 for i in items if XMLRPC.search(i["path"])),
                       "clients": len(clients),
                       "busiest_clients": dict(clients.most_common(_LIST))}))

        failures = Counter((x["domain"], x["src_ip"]) for x in attempts
                           if x["status"] in (200, 401, 403))
        wins: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for x in attempts:
            if x["status"] == 302 and not _in(x["src_ip"], trusted):
                wins[(x["domain"] or "?", x["src_ip"] or "?")].append(x)
        for (site, client), items in wins.items():
            failed_first = failures.get((site, client), 0)
            serious = failed_first >= LOGIN_FAILS_BEFORE or site in sprayed
            later_admin = [x for x in rows if x["src_ip"] == client and x["domain"] == site
                           and ADMIN.search(x["path"]) and 200 <= x["status"] < 300
                           and not STATIC.search(x["path"]) and x["ts"] >= items[0]["ts"]]
            r.signals.append(self._signal(
                f"web.login_success.{site}.{client}",
                f"Successful WordPress login on {site} from {client}",
                "web.login_success", Severity.HIGH if serious else Severity.MEDIUM, 0.7,
                items + later_admin,
                "WordPress answers a correct password with a 302 into wp-admin (a wrong "
                "one re-shows the form). Confirm this was the site's owner or a known "
                "editor; if not, the account is compromised - change its password, "
                "check for new admin users, plugins and edited theme files.",
                extra={"failed_attempts_before": failed_first, "site_sprayed": site in sprayed,
                       "admin_pages_after": len(later_admin)}))

    def _disguised(self, r: AnalyzerResult, by_client: dict[str, list[dict]]) -> None:
        ranges = crawlers.load()
        fakes: dict[str, list[dict]] = {}
        unchecked = False
        for client, items in by_client.items():
            claims = {crawlers.claimed_crawler(i.get("user_agent")) for i in items} - {None}
            for bot in claims:
                genuine = crawlers.is_genuine(client, bot, ranges)
                if genuine is None:
                    unchecked = True
                elif not genuine:
                    fakes[client] = [i for i in items
                                     if crawlers.claimed_crawler(i.get("user_agent")) == bot]
        if unchecked:
            r.notes.append("http_activity: crawler address lists unavailable, so Googlebot/"
                           "Bingbot user agents were not verified this run")
        if fakes:
            ranked = sorted(fakes.items(), key=lambda kv: -len(kv[1]))
            everything = sorted((i for _c, items in ranked for i in items), key=lambda i: i["ts"])
            r.signals.append(self._signal(
                "web.fake_crawler", f"{len(fakes)} client(s) posing as a search-engine crawler",
                "web.fake_crawler", Severity.LOW, 0.8, everything,
                "These requests claim to be Googlebot or Bingbot but come from addresses "
                "outside the ranges Google and Microsoft publish for them: scanners or "
                "scrapers borrowing a name that bot rules often wave through. Judge them "
                "by what they requested, not by the name.",
                extra={"by_client": [{"client": c, "claims": sorted({crawlers.claimed_crawler(
                    i.get("user_agent")) for i in items} - {None}), "requests": len(items),
                    "sensitive_probes": sum(1 for i in items if SENSITIVE.search(i["path"])),
                    "sites": sorted({i["domain"] for i in items if i.get("domain")})[:5]}
                    for c, items in ranked[:_LIST]]}))

        rotating = {c: items for c, items in by_client.items()
                    if len({i.get("user_agent") for i in items}) >= UA_ROTATION_MIN}
        if rotating:
            ranked = sorted(rotating.items(), key=lambda kv: -len({i.get("user_agent")
                                                                    for i in kv[1]}))
            everything = sorted((i for _c, items in ranked for i in items), key=lambda i: i["ts"])
            r.signals.append(self._signal(
                "web.ua_rotation", f"{len(rotating)} client(s) rotating user agents",
                "web.ua_rotation", Severity.LOW, 0.6, everything,
                "One address presenting many different browsers in a day is a tool "
                "dodging user-agent based blocking, not a person. Check what those "
                "clients requested alongside the scanner summary.",
                extra={"by_client": [{"client": c, "user_agents": len({i.get("user_agent")
                                                                      for i in items}),
                                      "requests": len(items),
                                      "not_found": sum(1 for i in items if i["status"] == 404)}
                                     for c, items in ranked[:_LIST]]}))

    def _new_scripts(self, r: AnalyzerResult, rows: list[dict], baseline: Baseline) -> None:
        ranges = crawlers.load()
        ran: dict[str, list[dict]] = defaultdict(list)
        for x in rows:
            bot = crawlers.claimed_crawler(x.get("user_agent"))
            if bot and crawlers.is_genuine(x["src_ip"], bot, ranges):
                continue          # same rule as the history (store.entity_pairs_from_events)
            key = script_endpoint(x["domain"], x["path"], x["program"], x["status"])
            if key:
                ran[key].append(x)
        if not ran:
            return
        if not baseline.has_history(EntityType.URL):
            r.notes.append(f"http_activity: first run recording web script endpoints "
                           f"({len(ran)} seen); new-script detection starts next run")
            return
        new = baseline.novel(EntityType.URL, sorted(ran))
        by_site: dict[str, list[str]] = defaultdict(list)
        for key in new:
            by_site[ran[key][0]["domain"] or "?"].append(key)
        for site, keys in by_site.items():
            items = sorted((i for k in keys for i in ran[k]), key=lambda i: i["ts"])
            posted = [k for k in keys if any(i["program"] == "POST" for i in ran[k])]
            r.signals.append(self._signal(
                f"web.new_script.{site}",
                f"{site}: {len(keys)} script(s) ran for the first time", "web.new_script",
                Severity.HIGH if posted else Severity.MEDIUM, 0.65, items,
                "Script files answering for the first time since DawnPatrol started "
                "recording. Usually a plugin or theme update; a web shell or an injected "
                "file looks exactly like this - especially one taking POSTs from a "
                "handful of addresses. Check each against a recent update; if none "
                "explains it, inspect the file on disk.",
                extra={"new_scripts": [{"path": k[len(site):], "requests": len(ran[k]),
                                        "methods": sorted({i["program"] for i in ran[k]}),
                                        "clients": sorted({i["src_ip"] for i in ran[k]})[:5]}
                                       for k in keys[:NEW_SCRIPTS_LISTED]],
                       "took_posts": [k[len(site):] for k in posted][:NEW_SCRIPTS_LISTED]}))

    def _admin(self, r: AnalyzerResult, rows: list[dict]) -> None:
        hits = [x for x in rows if ADMIN.search(x["path"]) and not STATIC.search(x["path"])
                and 200 <= x["status"] < 300]
        if not hits:
            return
        by_client: dict[str, list[dict]] = defaultdict(list)
        for x in hits:
            by_client[x["src_ip"] or "?"].append(x)
        ranked = sorted(by_client.items(), key=lambda kv: -len(kv[1]))
        r.signals.append(self._signal(
            "web.admin_access", f"Admin pages served to {len(by_client)} client(s)",
            "web.admin_access", Severity.LOW, 0.5, hits,
            "Admin pages answered 2xx. Expected from the owner's addresses and from "
            "uptime monitors named in the profile; from anyone else it means someone "
            "reached an admin panel - check those clients' other requests.",
            extra={"by_client": [{"client": c, "requests": len(items),
                                  "paths": sorted({i["path"].split("?", 1)[0]
                                                   for i in items})[:5],
                                  "user_agent": (items[0].get("user_agent") or "")[:80]}
                                 for c, items in ranked[:_LIST]]}))

    # ----- shared ----------------------------------------------------------- #

    def _signal(self, sid: str, title: str, taxonomy: str, severity: Severity,
                confidence: float, items: list[dict[str, Any]], hint: str,
                extra: dict[str, Any] | None = None) -> Signal:
        clients = sorted({i["src_ip"] for i in items if i.get("src_ip")})
        evidence: dict[str, Any] = {
            "requests": len(items),
            "clients": clients[:_LIST],
            "sites": sorted({i["domain"] for i in items if i.get("domain")})[:_LIST],
            "servers": sorted({i["device"] for i in items if i.get("device")})[:_LIST],
            "responses": dict(Counter(i["status"] for i in items).most_common(_LIST)),
            "methods": dict(Counter(i["program"] for i in items).most_common(5)),
            "sample_paths": [i["path"][:200] for i in items[:_LIST]],
            "user_agents": sorted({(i.get("user_agent") or "")[:120] for i in items
                                   if i.get("user_agent")})[:5],
            "first_seen": items[0]["ts"].strftime("%Y-%m-%d %H:%M UTC"),
            "last_seen": items[-1]["ts"].strftime("%Y-%m-%d %H:%M UTC"),
            **(extra or {}),
        }
        entities = [Entity(EntityType.IP, c, "client") for c in clients[:_LIST]]
        entities += [Entity(EntityType.DOMAIN, s, "site") for s in evidence["sites"]]
        return Signal(id=sid[:255], analyzer=self.name, title=title[:200], taxonomy=taxonomy,
                      severity_hint=severity, confidence=confidence, entities=entities,
                      evidence=evidence, narrative_hint=hint)


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _networks(values: list[str]) -> list[Any]:
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            continue
    return out


def _in(ip: str | None, nets: list[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _mb(n: int) -> str:
    return f"{n / 1024 / 1024:,.0f} MB"
