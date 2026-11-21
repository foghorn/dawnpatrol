"""ssh_host (journal + nginx access logs over SSH), the http_activity analyzer,
and user-agent / URL-marker IoC matching - against a fake SSH runner, so no
server, no network, no ssh binary needed."""

from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest

from dawnpatrol.analyzers.baseline import Baseline
from dawnpatrol.analyzers.http_activity import HttpActivityAnalyzer
from dawnpatrol.analyzers.ioc_match import IocMatchAnalyzer
from dawnpatrol.iocs import load_iocs
from dawnpatrol.models import EventKind, Severity
from dawnpatrol.query import EventQuery
from dawnpatrol.sources.ssh_host import SshHostSource, site_for


def nginx(ip, when, req, status=200, size=512, ua="Mozilla/5.0 (X11) Firefox/120", user="-"):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - {user} [{stamp}] "{req}" {status} {size} "-" "{ua}"'


def journal(when, ident, message, priority=6):
    return json.dumps({"__REALTIME_TIMESTAMP": str(int(when.timestamp() * 1e6)),
                       "__CURSOR": f"c-{ident}-{message[:20]}", "SYSLOG_IDENTIFIER": ident,
                       "PRIORITY": str(priority), "MESSAGE": message})


class FakeServer:
    """Answers the three commands the source sends, like a real host would."""

    def __init__(self, journal_lines, files, fail=None):
        self.journal_lines = journal_lines
        self.files = files                 # path -> list of lines
        self.fail = fail
        self.commands = []

    def __call__(self, argv, timeout):
        command = argv[-1]
        self.commands.append(command)
        if self.fail:
            return 255, "", self.fail
        if command.startswith("journalctl"):
            return 0, "\n".join(self.journal_lines) + "\n", ""
        if command.startswith("find"):
            return 0, "".join(f"100 {p}\n" for p in self.files), ""
        if "echo @@DAWNPATROL" in command:
            marker = re.search(r"echo (@@DAWNPATROL-\w+@@)", command).group(1)
            out = []
            for path, lines in self.files.items():
                if path in command:
                    out.append(f"{marker} {path}")
                    out += lines
            return 0, "\n".join(out) + "\n", ""
        if command.startswith("echo dawnpatrol-ok"):
            return 0, "dawnpatrol-ok\ndawnlogs adm systemd-journal\n", ""
        return 1, "", "unexpected command"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_HOSTS", "web1")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_HOST", "web.example.org")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_USER", "dawnlogs")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_IP", "198.51.100.10")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_HTTP_ROOTS", "/var/www/,/var/log/nginx")


def _source(profile, runner):
    src = SshHostSource(runner=runner)
    src.configure(profile)
    return src


def test_site_names_come_from_the_folder_layout():
    roots = ["/var/www", "/var/log/nginx"]
    assert site_for("/var/www/shop.example.org/logs/access.log", roots) == "shop.example.org"
    assert site_for("/var/www/blog/access.log.2.gz", roots) == "blog"
    assert site_for("/var/log/nginx/api.example.org.access.log", roots) == "api.example.org"
    assert site_for("/var/log/nginx/api.example.org-access.log.1", roots) == "api.example.org"
    assert site_for("/var/log/nginx/access.log", roots) == "default"


def test_collects_journal_and_http_from_one_server(env, profile, window):
    t = window.end - timedelta(hours=1)
    fake = FakeServer(
        journal_lines=[
            journal(t, "sshd", "Accepted publickey for deploy from 203.0.113.9 port 50422 ssh2"),
            journal(t, "sshd", "Failed password for root from 192.0.2.66 port 41000 ssh2"),
            journal(t, "sudo", "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
                               "COMMAND=/usr/bin/systemctl reload nginx"),
            journal(t, "nginx", "worker process 1234 exited on signal 9", priority=3),
            journal(window.start - timedelta(hours=2), "cron", "outside the window"),
            "not json",
        ],
        files={
            "/var/www/shop.example.org/logs/access.log": [
                nginx("203.0.113.50", t, "GET /products?id=3 HTTP/2.0"),
                nginx("203.0.113.50", window.start - timedelta(hours=3), "GET /old HTTP/1.1"),
                "garbage line",
            ],
            "/var/log/nginx/access.log.1": [
                nginx("192.0.2.7", t, 'GET /search?q=\\"x\\" HTTP/1.1', status=404,
                      ua="curl/8.0"),
            ],
        })
    result = _source(profile, fake).collect(window, ctx=None)
    by_kind = {}
    for e in result.events:
        by_kind.setdefault(e.kind, []).append(e)

    auth = {e.action: e for e in by_kind[EventKind.AUTH]}
    assert auth["ssh_accepted"].user == "deploy" and auth["ssh_accepted"].src_ip == "203.0.113.9"
    assert auth["ssh_failed"].user == "root" and auth["ssh_accepted"].device == "web1"
    system = by_kind[EventKind.SYSTEM]
    assert {e.action for e in system} == {"sudo", None}
    assert next(e for e in system if e.program == "nginx").severity == "err"

    http = sorted(by_kind[EventKind.HTTP], key=lambda e: e.domain)
    assert [e.domain for e in http] == ["default", "shop.example.org"]
    shop = http[1]
    assert shop.program == "GET" and shop.action == "200" and shop.pkt_len == 512
    assert shop.raw["path"] == "/products?id=3" and shop.dst_ip == "198.51.100.10"
    assert shop.src_zone == "external" and shop.user_agent.startswith("Mozilla/5.0")
    assert http[0].raw["path"] == '/search?q="x"' and http[0].user_agent == "curl/8.0"
    assert any("not in nginx combined format" in n for n in result.notes)
    assert result.errors == []
    # the find filter and window are applied server-side
    assert any("-newermt @" in c and "-maxdepth 4" in c for c in fake.commands)


def test_hostile_file_names_are_quoted(env, profile, window):
    evil = "/var/www/x/access.log; rm -rf ~"
    fake = FakeServer([], {evil: []})
    _source(profile, fake).collect(window, ctx=None)
    read = next(c for c in fake.commands if "zcat" in c)
    assert "'/var/www/x/access.log; rm -rf ~'" in read


def test_ssh_failure_is_an_error_not_an_empty_day(env, profile, window):
    fake = FakeServer([], {}, fail="Host key verification failed.")
    result = _source(profile, fake).collect(window, ctx=None)
    assert result.events == []
    assert any("Host key verification failed" in e for e in result.errors)


def test_ssh_command_pins_host_keys(env, profile):
    server = _source(profile, FakeServer([], {})).servers()[0]
    argv = server.ssh_argv("true")
    assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
    assert "UserKnownHostsFile=/etc/dawnpatrol/ssh/known_hosts" in argv
    assert argv[-2] == "dawnlogs@web.example.org"


def test_several_servers_are_configured_independently(monkeypatch, profile):
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_HOSTS", "web1, db1")
    for name, host in (("WEB1", "a.example"), ("DB1", "b.example")):
        monkeypatch.setenv(f"DAWNPATROL_SOURCE_SSH_{name}_HOST", host)
        monkeypatch.setenv(f"DAWNPATROL_SOURCE_SSH_{name}_USER", "logs")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_DB1_JOURNAL_UNITS", "postgresql.service")
    servers = {s.name: s for s in SshHostSource().servers()}
    assert servers["web1"].host == "a.example" and servers["db1"].host == "b.example"
    assert servers["db1"].journal_units == ["postgresql.service"]
    assert servers["db1"].http_roots == []


def test_probes_report_groups_and_found_sites(env, profile, window):
    fake = FakeServer(['{"__REALTIME_TIMESTAMP": "1"}'],
                      {"/var/www/shop/access.log": []})
    probes = {p.name: p for p in _source(profile, fake).self_test(ctx=None)}
    assert probes["web1-ssh"].ok and "systemd-journal" in probes["web1-ssh"].detail
    assert probes["web1-http-logs"].ok and probes["web1-http-logs"].detail == "shop"


# --------------------------------------------------------------------------- #
# http_activity
# --------------------------------------------------------------------------- #

def _analyze(store, profile, window, lines, analyzer=None):
    t = window.end - timedelta(hours=2)
    fake = FakeServer([], {"/var/www/shop/access.log": [
        nginx(ip, t + timedelta(seconds=i), req, status, size, **kw)
        for i, (ip, req, status, size, kw) in enumerate(lines)]})
    src = _source(profile, fake)
    store.start_run("web", 1, window.start, window)
    store.insert_events("web", src.collect(window, ctx=None).events)
    return (analyzer or HttpActivityAnalyzer()).run(EventQuery(store, "web"), profile,
                                                    Baseline(store, "web"))


def _tax(result):
    out = {}
    for s in result.signals:
        out.setdefault(s.taxonomy, []).append(s)
    return out


def test_scanner_noise_is_low_but_an_exposed_env_file_is_high(env, store, profile, window):
    lines = [("192.0.2.1", f"GET /probe{i} HTTP/1.1", 404, 0, {}) for i in range(40)]
    lines += [("192.0.2.1", "GET /.git/config HTTP/1.1", 404, 0, {}),
              ("192.0.2.2", "GET /.env HTTP/1.1", 200, 900, {})]
    tax = _tax(_analyze(store, profile, window, lines))
    assert tax["web.scanner"][0].severity_hint == Severity.LOW
    (exposed,) = tax["web.sensitive_exposure"]
    assert exposed.severity_hint == Severity.HIGH and exposed.evidence["clients"] == ["192.0.2.2"]


def test_injection_refused_is_low_but_reaching_the_app_is_medium(env, store, profile, window):
    tax = _tax(_analyze(store, profile, window, [
        ("192.0.2.3", "GET /?id=1%20union%20select%201 HTTP/1.1", 403, 0, {}),
        ("192.0.2.4", "GET /download?f=../../etc/passwd HTTP/1.1", 500, 0, {}),
    ]))
    sev = {s.evidence["clients"][0]: s.severity_hint for s in tax["web.injection_attempt"]}
    assert sev == {"192.0.2.3": Severity.LOW, "192.0.2.4": Severity.MEDIUM}


def test_script_answering_in_uploads_is_a_webshell_shape(env, store, profile, window):
    tax = _tax(_analyze(store, profile, window, [
        ("192.0.2.5", "POST /wp-content/uploads/2026/x.php HTTP/1.1", 200, 40, {}),
        ("192.0.2.6", "GET /uploads/photo.jpg HTTP/1.1", 200, 9000, {}),
        ("192.0.2.7", "GET /uploads/missing.php HTTP/1.1", 404, 0, {}),
    ]))
    (shell,) = tax["web.webshell"]
    assert shell.severity_hint == Severity.HIGH and shell.evidence["clients"] == ["192.0.2.5"]


def test_login_bruteforce_errors_and_metrics(env, store, profile, window):
    lines = [("192.0.2.8", "POST /wp-login.php HTTP/1.1", 200, 100, {}) for _ in range(25)]
    lines += [("192.0.2.9", "GET /api HTTP/1.1", 502, 0, {}) for _ in range(25)]
    result = _analyze(store, profile, window, lines)
    tax = _tax(result)
    assert tax["web.login_bruteforce"][0].severity_hint == Severity.MEDIUM
    assert tax["web.server_errors"][0].evidence["site_requests"] == 50
    metrics = {m.key: m.value for m in result.metrics}
    assert metrics["http.requests"] == 50 and metrics["http.5xx"] == 25
    assert metrics["http.site.shop"] == 50


# --------------------------------------------------------------------------- #
# User-agent and URL-marker indicators
# --------------------------------------------------------------------------- #

LIST = """indicator,type,tier,source,campaign,warning
Mozilla/5.0 (ARTEX),user-agent,T1,Vendor,Camp,
curl/7.88.1,user-agent,T4,Vendor,Camp,generic
k=x9f3c2b7e,string-marker,T1,Vendor,Camp,
artx_* / artx-* / zzartx<n>.php,string-marker,T2,Vendor,Camp,
"""


def test_user_agent_and_url_marker_indicators(env, store, profile, window, tmp_path):
    path = tmp_path / "l.csv"
    path.write_text(LIST, encoding="utf-8")
    iocs = load_iocs([path])
    assert {(i.kind, i.value) for i in iocs.indicators} == {
        ("user_agent", "mozilla/5.0 (artex)"), ("url_marker", "k=x9f3c2b7e"),
        ("url_marker", "zzartx")}
    assert "user-agent (T4, enrichment only)" in iocs.skipped_types

    result = _analyze(store, profile, window, [
        ("192.0.2.10", "GET /shell.php?k=x9f3c2b7e&c=id HTTP/1.1", 200, 10, {}),
        ("192.0.2.11", "GET / HTTP/1.1", 200, 10, {"ua": "Mozilla/5.0 (ARTEX)"}),
        ("192.0.2.12", "GET / HTTP/1.1", 200, 10, {"ua": "curl/7.88.1"}),
        ("192.0.2.13", "GET /zzartx7.php HTTP/1.1", 404, 0, {}),
    ], analyzer=IocMatchAnalyzer(iocs))
    by_id = {s.id: s for s in result.signals}
    ua = by_id["ioc.user_agent.mozilla/5.0 (artex)"]
    assert ua.severity_hint == Severity.CRITICAL and ua.evidence["clients"] == ["192.0.2.11"]
    marker = by_id["ioc.url_marker.k=x9f3c2b7e"]
    assert marker.evidence["responses"] == {"200": 1} and marker.evidence["sites"] == ["shop"]
    assert by_id["ioc.url_marker.zzartx"].severity_hint == Severity.HIGH
    assert not any("curl" in sid for sid in by_id)      # T4: enrichment only


# --------------------------------------------------------------------------- #
# Hosting layouts: symlinked log folders, duplicate rotated copies, denials
# --------------------------------------------------------------------------- #

def test_follow_symlinks_is_opt_in(env, monkeypatch, profile):
    plain = _source(profile, FakeServer([], {})).servers()[0]
    assert plain.find_command(0).startswith("find /var/www")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_HTTP_FOLLOW_SYMLINKS", "true")
    linked = _source(profile, FakeServer([], {})).servers()[0]
    assert linked.find_command(0).startswith("find -L /var/www")


def test_a_rotated_log_kept_under_two_names_is_counted_once(env, profile, window):
    t = window.end - timedelta(hours=1)
    day = [nginx("192.0.2.20", t, "GET / HTTP/1.1"),
           nginx("192.0.2.20", t, "GET / HTTP/1.1"),        # a real repeat, kept
           nginx("192.0.2.21", t, "GET /a HTTP/1.1")]
    fake = FakeServer([], {
        "/var/www/blog/https/access.log.0": day,
        "/var/www/blog/https/access.log.2026-11-20": day,     # same content, second name
        "/var/www/blog/http/access.log.0": day[:1],            # other folder: kept
    })
    result = _source(profile, fake).collect(window, ctx=None)
    http = [e for e in result.events if e.kind == EventKind.HTTP]
    assert len(http) == 4
    assert any("3 line(s) were copies" in n for n in result.notes)


def test_unreadable_log_folders_are_reported(env, profile, window):
    class Denying(FakeServer):
        def __call__(self, argv, timeout):
            if argv[-1].startswith("find"):
                return 0, ("! '/var/www/private/http': Permission denied\n"
                           "100 /var/www/blog/access.log\n"), ""
            return super().__call__(argv, timeout)

    fake = Denying([], {"/var/www/blog/access.log": []})
    result = _source(profile, fake).collect(window, ctx=None)
    assert any("could not read 1 log location" in n and "/var/www/private/http" in n
               for n in result.notes)


# --------------------------------------------------------------------------- #
# contrib/dawnpatrol-ssh-guard.sh must allow exactly what the source sends
# --------------------------------------------------------------------------- #

GUARD = __import__("pathlib").Path(__file__).parent.parent / "contrib" / "dawnpatrol-ssh-guard.sh"


def _guard(cmd, tmp_path, roots="/var/www"):
    import os
    import subprocess
    env = {**os.environ, "DAWNPATROL_GUARD_DRYRUN": "1", "DAWNPATROL_GUARD_ROOTS": roots,
           "HOME": str(tmp_path), "SSH_ORIGINAL_COMMAND": cmd}
    out = subprocess.run(["bash", str(GUARD)], env=env, capture_output=True, text=True)
    return out.stdout.strip() == "ALLOW"


def test_the_guard_allows_every_command_the_source_sends(env, monkeypatch, profile,
                                                         window, tmp_path):
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_HTTP_ROOTS", "/var/www")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_HTTP_FOLLOW_SYMLINKS", "true")
    monkeypatch.setenv("DAWNPATROL_SOURCE_SSH_WEB1_JOURNAL_UNITS", "ssh.service,nginx.service")
    t = window.end - timedelta(hours=1)
    fake = FakeServer([journal(t, "sshd", "x")],
                      {"/var/www/blog/https/access.log": [nginx("192.0.2.1", t, "GET / HTTP/1.1")],
                       "/var/www/my site/access.log.1": []})
    src = _source(profile, fake)
    src.collect(window, ctx=None)
    src.self_test(ctx=None)
    assert len(fake.commands) >= 5
    for cmd in fake.commands:
        assert _guard(cmd, tmp_path), cmd


@pytest.mark.parametrize("cmd", [
    "bash", "cat ~/.ssh/authorized_keys", "id; rm -rf ~",
    "find /etc -maxdepth 4 -type f -name x -printf '%s %p\\\\n' 2>&1 | sed 's/^find: /! /'",
    "echo @@DAWNPATROL-00@@ /etc/passwd; zcat -f -- /etc/passwd 2>/dev/null | tail -n 5",
    "echo @@DAWNPATROL-00@@ /var/www/../../etc/shadow; "
    "zcat -f -- /var/www/../../etc/shadow 2>/dev/null | tail -n 5",
    "echo @@DAWNPATROL-00@@ /var/www/$(id); zcat -f -- /var/www/x 2>/dev/null | tail -n 5",
])
def test_the_guard_refuses_everything_else(cmd, tmp_path):
    assert not _guard(cmd, tmp_path)


# --------------------------------------------------------------------------- #
# Noise is summarized: one signal for all scanners, one for admin access
# --------------------------------------------------------------------------- #

def test_many_scanners_make_one_summary_signal(env, store, profile, window):
    lines = [(f"192.0.2.{c}", f"GET /p{i} HTTP/1.1", 404, 0, {})
             for c in range(1, 41) for i in range(35)]
    lines.append(("192.0.2.99", "GET /.env HTTP/1.1", 200, 900, {}))
    tax = _tax(_analyze(store, profile, window, lines))
    (summary,) = tax["web.scanner"]
    assert summary.id == "web.scanners" and summary.evidence["scanning_clients"] == 40
    assert len(summary.evidence["top_scanners"]) == 10
    assert len(tax["web.sensitive_exposure"]) == 1      # the one that matters stays separate


def test_admin_rule_skips_lookalikes_and_static_files(env, store, profile, window):
    tax = _tax(_analyze(store, profile, window, [
        ("192.0.2.30", "GET /wp-admin-cron.php HTTP/1.1", 200, 10, {}),
        ("192.0.2.31", "GET /wp-admin/css/login.min.css HTTP/1.1", 200, 10, {}),
        ("192.0.2.32", "GET /wp-admin/healthcheck.php HTTP/1.1", 200, 10,
         {"ua": "Mozilla/5.0+(compatible; UptimeRobot/2.0)"}),
        ("192.0.2.33", "GET /wp-admin/ HTTP/1.1", 200, 10, {}),
    ]))
    (admin,) = tax["web.admin_access"]
    clients = {c["client"] for c in admin.evidence["by_client"]}
    assert clients == {"192.0.2.32", "192.0.2.33"}


def test_the_bundle_says_what_the_signal_cap_left_out():
    from datetime import UTC, datetime, timedelta

    from dawnpatrol.agent import bundle
    from dawnpatrol.models import Signal, Window
    from dawnpatrol.profile import Profile
    sigs = [Signal(id=f"s.high.{i}", analyzer="a", title="t", taxonomy="x.high",
                   severity_hint=Severity.HIGH) for i in range(bundle.MAX_SIGNALS)]
    sigs += [Signal(id=f"s.low.{i}", analyzer="a", title="t", taxonomy="web.scanner",
                    severity_hint=Severity.LOW) for i in range(7)]
    sigs.append(Signal(id="canary", analyzer="a", title="t", taxonomy="c", is_canary=True))
    end = datetime(2026, 6, 1, tzinfo=UTC)
    text = bundle.build_bundle(window=Window(start=end - timedelta(hours=24), end=end),
                               health=[], metrics=[], signals=sigs, profile=Profile(),
                               notes=[], watchlist=[], enrichment_budgets={},
                               baseline_available=True, run_id="r")
    assert f"({bundle.MAX_SIGNALS} shown of {bundle.MAX_SIGNALS + 7})" in text
    assert "Not shown, all lower-ranked than those below: 7 web.scanner (LOW)" in text


def test_crawlers_and_the_server_itself_are_not_scanners(env, store, profile, window):
    lines = [("66.249.68.70", f"GET /article-{i} HTTP/1.1", 200, 900, {"ua": "Googlebot/2.1"})
             for i in range(80)]                                   # many pages, no probing
    lines += [("198.51.100.10", f"GET /wp-cron.php?doing_wp_cron={i} HTTP/1.1", 404, 0, {})
              for i in range(40)]                                  # the server calling itself
    lines += [("192.0.2.50", p, 404, 0, {}) for p in
              ("GET /.git/HEAD HTTP/1.1", "GET /.env HTTP/1.1", "GET /.aws/credentials HTTP/1.1")]
    tax = _tax(_analyze(store, profile, window, lines))
    (summary,) = tax["web.scanner"]
    assert [c["client"] for c in summary.evidence["top_scanners"]] == ["192.0.2.50"]
    assert summary.evidence["top_scanners"][0]["sensitive_probes"] == 3


# --------------------------------------------------------------------------- #
# WordPress login attacks, disguised clients, new script endpoints
# --------------------------------------------------------------------------- #

def test_distributed_login_spray_and_a_successful_login(env, store, profile, window,
                                                        monkeypatch):
    monkeypatch.setenv("DAWNPATROL_WEB_TRUSTED_CLIENTS", "203.0.113.0/24")
    lines = [(f"192.0.2.{c}", "POST /wp-login.php HTTP/1.1", 200, 5000, {}) for c in range(1, 36)]
    lines += [("198.51.100.200", "POST /xmlrpc.php HTTP/1.1", 200, 400, {})]
    lines += [("192.0.2.5", "POST /wp-login.php HTTP/1.1", 200, 5000, {}) for _ in range(3)]
    lines += [("192.0.2.5", "POST /wp-login.php HTTP/1.1", 302, 0, {}),
              ("192.0.2.5", "GET /wp-admin/ HTTP/1.1", 200, 9000, {}),
              ("203.0.113.7", "POST /wp-login.php HTTP/1.1", 302, 0, {}),          # the owner
              ("192.0.2.77", "POST /wp-login.php?action=lostpassword HTTP/1.1", 302, 0, {})]
    tax = _tax(_analyze(store, profile, window, lines))
    (spray,) = tax["web.login_spray"]
    assert spray.evidence["xmlrpc_posts"] == 1 and spray.evidence["clients"] >= 35
    (win,) = tax["web.login_success"]
    assert win.severity_hint == Severity.HIGH
    assert win.evidence["failed_attempts_before"] == 4 and win.evidence["admin_pages_after"] == 1


def test_a_lone_successful_login_is_medium(env, store, profile, window):
    tax = _tax(_analyze(store, profile, window, [
        ("192.0.2.60", "POST /wp-login.php HTTP/1.1", 302, 0, {})]))
    assert tax["web.login_success"][0].severity_hint == Severity.MEDIUM
    assert "web.login_spray" not in tax


def test_fake_crawlers_and_user_agent_rotation(env, store, profile, window, monkeypatch,
                                               tmp_path):
    from dawnpatrol import crawlers
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path))
    crawlers.cache_path(tmp_path).write_text(json.dumps(
        {"fetched_at": "2026-06-01T00:00:00+00:00",
         "ranges": {"googlebot": ["66.249.64.0/19"], "bingbot": ["157.55.39.0/24"]}}))
    gb = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    lines = [("66.249.66.1", "GET / HTTP/1.1", 200, 10, {"ua": gb}),
             ("192.0.2.9", "GET /.env HTTP/1.1", 404, 0, {"ua": gb}),
             ("192.0.2.9", "GET / HTTP/1.1", 200, 10, {"ua": gb})]
    lines += [("192.0.2.44", f"GET /p{i} HTTP/1.1", 200, 10, {"ua": f"Mozilla/5.0 Tool{i}"})
              for i in range(12)]
    tax = _tax(_analyze(store, profile, window, lines))
    (fake,) = tax["web.fake_crawler"]
    assert [c["client"] for c in fake.evidence["by_client"]] == ["192.0.2.9"]
    assert fake.evidence["by_client"][0]["sensitive_probes"] == 1
    (rot,) = tax["web.ua_rotation"]
    assert rot.evidence["by_client"][0] == {"client": "192.0.2.44", "user_agents": 12,
                                            "requests": 12, "not_found": 0}


def test_crawler_claims_are_skipped_without_lists(env, store, profile, window, monkeypatch,
                                                  tmp_path):
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path / "empty"))
    result = _analyze(store, profile, window, [
        ("192.0.2.9", "GET / HTTP/1.1", 200, 10, {"ua": "Googlebot/2.1"})])
    assert "web.fake_crawler" not in _tax(result)
    assert any("crawler address lists unavailable" in n for n in result.notes)


def test_new_script_endpoints_after_the_first_recording_run(env, store, profile, window):
    from dawnpatrol.store import entity_pairs_from_events, script_endpoint
    assert script_endpoint("s", "/a.php?x=1", "GET", "200") == "s/a.php"
    assert script_endpoint("s", "/a.php", "GET", "404") is None
    assert script_endpoint("s", "/a.php", "POST", "302") == "s/a.php"
    assert script_endpoint("s", "/page", "GET", "200") is None

    # First recording run: nothing to compare with, so it only seeds history.
    first = _analyze(store, profile, window,
                     [("192.0.2.1", "GET /index.php HTTP/1.1", 200, 10, {})])
    assert "web.new_script" not in _tax(first)
    assert any("first run recording web script endpoints" in n for n in first.notes)
    store.observe_entities([(EntityType_URL(), "shop/index.php", 1)],
                           window.end - timedelta(days=2))

    # A later run: the known script is quiet, two new ones are reported.
    t = window.end - timedelta(hours=1)
    fake = FakeServer([], {"/var/www/shop/access.log": [
        nginx("192.0.2.1", t, "GET /index.php HTTP/1.1"),
        nginx("192.0.2.2", t, "GET /wp-content/plugins/new/info.php HTTP/1.1"),
        nginx("192.0.2.3", t, "POST /wp-content/themes/x/cache.php HTTP/1.1", 200, 20)]})
    events = _source(profile, fake).collect(window, ctx=None).events
    store.start_run("web2", 2, window.start, window)
    store.insert_events("web2", events)
    from datetime import UTC, datetime
    store.observe_entities(entity_pairs_from_events(events), datetime.now(UTC))  # as the runner does
    result = HttpActivityAnalyzer().run(EventQuery(store, "web2"), profile,
                                        Baseline(store, "web2"))
    (sig,) = _tax(result)["web.new_script"]
    assert sig.severity_hint == Severity.HIGH
    assert sorted(n["path"] for n in sig.evidence["new_scripts"]) == [
        "/wp-content/plugins/new/info.php", "/wp-content/themes/x/cache.php"]
    assert sig.evidence["took_posts"] == ["/wp-content/themes/x/cache.php"]


def EntityType_URL():
    from dawnpatrol.models import EntityType
    return EntityType.URL


def test_crawler_lists_refresh_weekly_and_survive_failures(tmp_path, monkeypatch):
    import httpx

    from dawnpatrol import crawlers
    monkeypatch.delenv("DAWNPATROL_CRAWLER_RANGES", raising=False)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if "fail" in str(calls.get("mode", "")):
            return httpx.Response(500)
        return httpx.Response(200, json={"prefixes": [{"ipv4Prefix": "66.249.64.0/19"},
                                                      {"ipv6Prefix": "2001:4860:4801::/48"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    from datetime import UTC, datetime
    now = datetime(2026, 6, 1, tzinfo=UTC)
    assert crawlers.refresh(tmp_path, client=client, now=now) == "updated"
    assert crawlers.refresh(tmp_path, client=client, now=now + timedelta(days=1)) == "fresh"
    calls["mode"] = "fail"
    assert crawlers.refresh(tmp_path, client=client, now=now + timedelta(days=8)) \
        == "failed (kept previous copy)"
    ranges = crawlers.load(tmp_path)
    assert crawlers.is_genuine("66.249.66.1", "googlebot", ranges) is True
    assert crawlers.is_genuine("192.0.2.9", "googlebot", ranges) is False


def test_absolute_form_request_targets_are_reduced_to_the_path(env, profile, window):
    t = window.end - timedelta(hours=1)
    fake = FakeServer([], {"/var/www/shop/access.log": [
        nginx("192.0.2.1", t, "GET https://www.shop.example/wp-admin/healthcheck.php HTTP/1.1")]})
    (ev,) = _source(profile, fake).collect(window, ctx=None).events
    assert ev.raw["path"] == "/wp-admin/healthcheck.php"
    assert ev.raw["request_host"] == "www.shop.example"


def test_verified_crawlers_do_not_make_scripts_new(env, store, profile, window, monkeypatch,
                                                   tmp_path):
    from datetime import UTC, datetime

    from dawnpatrol import crawlers
    from dawnpatrol.models import EntityType
    from dawnpatrol.store import entity_pairs_from_events
    monkeypatch.setenv("DAWNPATROL_DATA_DIR", str(tmp_path))
    crawlers.cache_path(tmp_path).write_text(json.dumps(
        {"fetched_at": "2026-06-01T00:00:00+00:00", "ranges": {"googlebot": ["66.249.64.0/19"]}}))
    store.observe_entities([(EntityType.URL, "shop/index.php", 1)],
                           datetime.now(UTC) - timedelta(days=2))
    t = window.end - timedelta(hours=1)
    gb = "Mozilla/5.0 (compatible; Googlebot/2.1)"
    fake = FakeServer([], {"/var/www/shop/access.log": [
        nginx("66.249.66.1", t, "GET /wp-content/plugins/jp/class-helper.php HTTP/1.1", ua=gb),
        nginx("192.0.2.9", t, "GET /wp-content/plugins/jp/other.php HTTP/1.1", ua=gb)]})  # fake bot
    events = _source(profile, fake).collect(window, ctx=None).events
    pairs = {v for t_, v, _c in entity_pairs_from_events(events) if t_ == EntityType.URL}
    assert pairs == {"shop/wp-content/plugins/jp/other.php"}
    store.start_run("web3", 3, window.start, window)
    store.insert_events("web3", events)
    store.observe_entities(entity_pairs_from_events(events), datetime.now(UTC))
    result = HttpActivityAnalyzer().run(EventQuery(store, "web3"), profile, Baseline(store, "web3"))
    (sig,) = _tax(result)["web.new_script"]
    assert [n["path"] for n in sig.evidence["new_scripts"]] == ["/wp-content/plugins/jp/other.php"]
