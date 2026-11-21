"""Remote servers read over SSH: the systemd journal and nginx access logs.

For a machine DawnPatrol can only reach by SSH - a web server in a datacenter,
a VPS. Each run opens a few SSH sessions per server (OpenSSH's own ``ssh``
client, so keys, host-key pinning and ``~/.ssh/config`` jump hosts all work as
usual) and reads:

* the **journal** for the window (``journalctl -o json``): sshd lines become
  ``AUTH`` events through the same parser the router's syslog uses, so the
  SSH logon checks in ``auth_activity`` cover these servers too; sudo lines
  become ``SYSTEM`` events with ``action=sudo``; everything else is ``SYSTEM``.
* **nginx access logs** in the "combined" format, found under configurable
  root folders and their sub-folders, rotated and gzipped files included.
  Only files modified inside the window are read, filtered on the server by
  ``find -newermt``. Each request becomes an ``HTTP`` event; the site comes
  from the folder layout (see ``site_for``).

Settings. ``DAWNPATROL_SOURCE_SSH_HOSTS`` lists server names (it also switches
the source on); each name has its own block, ``DAWNPATROL_SOURCE_SSH_<NAME>_``:

* ``HOST`` (required), ``PORT`` (22), ``USER`` (required)
* ``KEY_FILE``: private key; unset uses the container user's ``~/.ssh``
* ``KNOWN_HOSTS``: known_hosts file pinning the server's host key
  (default ``/etc/dawnpatrol/ssh/known_hosts``). Host keys are never accepted
  on first use: an unknown or changed key fails the run for that server.
* ``IP``: the server's address, recorded as each request's destination
* ``JOURNAL`` (true) and ``JOURNAL_UNITS`` (optional unit list)
* ``HTTP_ROOTS``: folders to search (empty: no HTTP collection)
* ``HTTP_PATTERN`` (``*access*.log*``) and ``HTTP_MAX_DEPTH`` (4)
* ``HTTP_FOLLOW_SYMLINKS`` (false): follow symlinked folders and files, for
  hosts that link each site's live logs in from elsewhere (DreamHost:
  ``~/logs/<site>/https -> /home/_domain_logs/...``)
* ``MAX_LINES``: per journal and per log file (default 300000); hitting it
  marks the collection incomplete instead of truncating silently
* ``TIMEOUT``: seconds per SSH session (default 300)

Setting up the server side (a read-only account, key, host-key pin) is in
docs/ssh-setup.md.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets as pysecrets
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..context import RunContext
from ..models import CollectionResult, Event, EventKind, Probe, Window
from ..secrets import read_bool, read_env, read_int, read_list
from .base import Source
from .librenms_syslog import parse_openssh

log = logging.getLogger(__name__)

ENV = "DAWNPATROL_SOURCE_SSH_"
DEFAULT_KNOWN_HOSTS = "/etc/dawnpatrol/ssh/known_hosts"
_PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
_LOG_SUFFIX = re.compile(r"([._-]?access)?([._-]log)?(\.\d+)?(\.gz)?$", re.I)

#: Runs a command on a server; returns (exit code, stdout, stderr).
Runner = Callable[[list[str], int], tuple[int, str, str]]


def _subprocess_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


@dataclass
class SshServer:
    name: str
    host: str
    user: str
    port: int = 22
    key_file: str = ""
    known_hosts: str = DEFAULT_KNOWN_HOSTS
    ip: str = ""
    journal: bool = True
    journal_units: list[str] = field(default_factory=list)
    http_roots: list[str] = field(default_factory=list)
    http_pattern: str = "*access*.log*"
    http_max_depth: int = 4
    http_follow_symlinks: bool = False
    max_lines: int = 300_000
    timeout: int = 300

    @classmethod
    def from_env(cls, name: str) -> SshServer:
        p = f"{ENV}{name.upper()}_"
        return cls(
            name=name, host=read_env(f"{p}HOST", "") or "",
            user=read_env(f"{p}USER", "") or "", port=read_int(f"{p}PORT", 22),
            key_file=read_env(f"{p}KEY_FILE", "") or "",
            known_hosts=read_env(f"{p}KNOWN_HOSTS", DEFAULT_KNOWN_HOSTS) or DEFAULT_KNOWN_HOSTS,
            ip=read_env(f"{p}IP", "") or "",
            journal=read_bool(f"{p}JOURNAL", True),
            journal_units=read_list(f"{p}JOURNAL_UNITS"),
            http_roots=[r.rstrip("/") or "/" for r in read_list(f"{p}HTTP_ROOTS")],
            http_pattern=read_env(f"{p}HTTP_PATTERN", "*access*.log*") or "*access*.log*",
            http_max_depth=read_int(f"{p}HTTP_MAX_DEPTH", 4),
            http_follow_symlinks=read_bool(f"{p}HTTP_FOLLOW_SYMLINKS", False),
            max_lines=read_int(f"{p}MAX_LINES", 300_000),
            timeout=read_int(f"{p}TIMEOUT", 300),
        )

    def find_command(self, since_epoch: int | None = None, limit: int | None = None) -> str:
        """``find`` over the HTTP roots, printing ``<size> <path>`` per log file.
        Errors (unreadable folders) go to stdout prefixed ``!``, so they can be
        reported instead of silently missing a site."""
        roots = " ".join(shlex.quote(r) for r in self.http_roots)
        follow = "-L " if self.http_follow_symlinks else ""
        newer = f"-newermt @{since_epoch} " if since_epoch is not None else ""
        cmd = (f"find {follow}{roots} -maxdepth {self.http_max_depth} -type f "
               f"-name {shlex.quote(self.http_pattern)} {newer}"
               f"-printf '%s %p\\n' 2>&1 | sed 's/^find: /! /'")
        return cmd + (f" | head -n {limit}" if limit else "")

    def ssh_argv(self, command: str) -> list[str]:
        argv = ["ssh", "-C", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "ConnectTimeout=20",
                "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR", "-p", str(self.port)]
        if self.key_file:
            argv += ["-i", self.key_file, "-o", "IdentitiesOnly=yes"]
        return argv + [f"{self.user}@{self.host}", command]


class SshHostSource(Source):
    name = "ssh_host"
    kinds = frozenset({EventKind.HTTP, EventKind.AUTH, EventKind.SYSTEM})
    requires_env = frozenset({f"{ENV}HOSTS"})
    min_expected_records = 0

    def __init__(self, runner: Runner | None = None) -> None:
        super().__init__()
        self.runner: Runner = runner or _subprocess_runner

    def servers(self) -> list[SshServer]:
        return [SshServer.from_env(n) for n in read_list(f"{ENV}HOSTS")]

    # ----- collection ------------------------------------------------------- #

    def collect(self, window: Window, ctx: RunContext) -> CollectionResult:
        result = CollectionResult(source=self.name, window=window, requested_window=window)
        for server in self.servers():
            if not server.host or not server.user:
                result.errors.append(f"{server.name}: HOST and USER must both be set")
                continue
            if server.journal:
                self._collect_journal(server, window, result)
            if server.http_roots:
                self._collect_http(server, window, result)
        result.reported_total = len(result.events)
        return result

    def _run(self, server: SshServer, command: str) -> tuple[int, str, str]:
        try:
            return self.runner(server.ssh_argv(command), server.timeout)
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {server.timeout}s"
        except OSError as exc:
            return 127, "", f"{type(exc).__name__}: {exc}"

    def _collect_journal(self, server: SshServer, window: Window,
                         result: CollectionResult) -> None:
        units = " ".join(f"-u {shlex.quote(u)}" for u in server.journal_units)
        cmd = (f"journalctl --utc --no-pager -o json "
               f"--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM,PRIORITY,_PID,_SYSTEMD_UNIT "
               f"--since @{int(window.start.timestamp())} --until @{int(window.end.timestamp())} "
               f"{units} | head -n {server.max_lines + 1}")
        code, out, err = self._run(server, cmd)
        lines = out.splitlines()
        if code != 0 and not lines:
            result.errors.append(f"{server.name}: journal read failed: {_first_line(err, code)}")
            result.complete = False
            return
        if len(lines) > server.max_lines:
            lines = lines[:server.max_lines]
            result.complete = False
            result.errors.append(f"{server.name}: journal stopped at the {server.max_lines}-line "
                                 f"cap ({ENV}{server.name.upper()}_MAX_LINES)")
        result.pages += 1
        kept = 0
        for line in lines:
            event = self.normalize_journal(server, line)
            if event is not None and window.start <= event.ts < window.end:
                result.events.append(event)
                kept += 1
        result.notes.append(f"{server.name}: {kept} journal entries")

    def _collect_http(self, server: SshServer, window: Window,
                      result: CollectionResult) -> None:
        code, out, err = self._run(server, server.find_command(int(window.start.timestamp())))
        files, denied = _parse_listing(out)
        if denied:
            result.notes.append(f"{server.name}: could not read {len(denied)} log location(s), "
                                f"so their sites are not covered: {'; '.join(denied[:5])}")
        if not files:
            if code not in (0, 1):
                result.errors.append(f"{server.name}: listing HTTP logs failed: "
                                     f"{_first_line(err, code)}")
            result.notes.append(f"{server.name}: no access log under "
                                f"{', '.join(server.http_roots)} changed in the window")
            return
        marker = f"@@DAWNPATROL-{pysecrets.token_hex(8)}@@"
        script = "; ".join(
            f"echo {marker} {shlex.quote(f)}; zcat -f -- {shlex.quote(f)} 2>/dev/null "
            f"| tail -n {server.max_lines + 1}" for f in files)
        code, out, err = self._run(server, script)
        if code != 0 and marker not in out:
            result.errors.append(f"{server.name}: reading HTTP logs failed: "
                                 f"{_first_line(err, code)}")
            result.complete = False
            return
        per_file: dict[str, list[str]] = {}
        current = None
        for line in out.splitlines():
            if line.startswith(marker + " "):
                current = line[len(marker) + 1:]
                per_file[current] = []
            elif current is not None:
                per_file[current].append(line)
        kept = bad = dupes = 0
        sites: set[str] = set()
        # Hosts often keep one rotated log under two names (access.log.0 and
        # access.log.2026-11-20); count each line once per folder.
        seen: set[tuple[str, str, int]] = set()
        for path, lines in per_file.items():
            result.pages += 1
            if len(lines) > server.max_lines:
                lines = lines[-server.max_lines:]
                result.complete = False
                result.errors.append(f"{server.name}: {path} has more than {server.max_lines} "
                                     f"lines; only the newest were read")
            site = site_for(path, server.http_roots)
            folder = path.rsplit("/", 1)[0]
            occurrences: dict[str, int] = {}
            for n, line in enumerate(lines):
                occurrences[line] = occurrences.get(line, 0) + 1
                key = (folder, line, occurrences[line])
                if key in seen:
                    dupes += 1
                    continue
                seen.add(key)
                event = self.normalize_access(server, site, path, n, line)
                if event is None:
                    bad += 1 if line.strip() else 0
                    continue
                if window.start <= event.ts < window.end:
                    result.events.append(event)
                    sites.add(site)
                    kept += 1
        result.notes.append(f"{server.name}: {kept} HTTP requests from {len(per_file)} "
                            f"log file(s), sites: {', '.join(sorted(sites)) or 'none'}")
        if bad:
            result.notes.append(f"{server.name}: {bad} access-log line(s) were not in nginx "
                                f"combined format and were skipped")
        if dupes:
            result.notes.append(f"{server.name}: {dupes} line(s) were copies of lines already "
                                f"read from another file in the same folder, and were "
                                f"counted once")

    # ----- normalization ---------------------------------------------------- #

    def normalize_journal(self, server: SshServer, line: str) -> Event | None:
        try:
            rec = json.loads(line)
            ts = datetime.fromtimestamp(int(rec["__REALTIME_TIMESTAMP"]) / 1e6, UTC)
        except (ValueError, KeyError, TypeError):
            return None
        message = rec.get("MESSAGE")
        if isinstance(message, list):          # journald's form for non-UTF-8 text
            message = bytes(x for x in message if isinstance(x, int)).decode("utf-8", "replace")
        message = str(message or "")
        program = str(rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "unknown")
        try:
            severity = _PRIORITIES[int(rec.get("PRIORITY", 6))]
        except (ValueError, IndexError):
            severity = None
        common: dict[str, Any] = {
            "ts": ts, "source": self.name,
            "dedup_key": Event.make_dedup_key(self.name, server.name,
                                              rec.get("__CURSOR") or line),
            "device": server.name, "program": program[:128], "severity": severity,
            "message": message[:1000],
            "raw": {"server": server.name, "unit": rec.get("_SYSTEMD_UNIT"),
                    "pid": rec.get("_PID")},
        }
        if program.lower().startswith("sshd"):
            event = parse_openssh(message, common, self.assign_zones)
            if event is not None:
                return event
        if program == "sudo" and (m := _SUDO.match(message)):
            return Event(kind=EventKind.SYSTEM, action="sudo", user=m.group("user")[:255],
                         **common)
        return Event(kind=EventKind.SYSTEM, **common)

    def normalize_access(self, server: SshServer, site: str, path: str, n: int,
                         line: str) -> Event | None:
        m = _COMBINED.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        except ValueError:
            return None
        request = _unescape(m.group("req"))
        parts = request.split(" ")
        method, target, protocol = (parts + ["", ""])[:3] if len(parts) >= 2 else ("", request, "")
        if not re.fullmatch(r"[A-Z]{3,10}", method or ""):
            method, target, protocol = "", request, ""
        # Absolute-form targets ("GET https://site/path HTTP/1.1", sent by
        # proxies and some monitors) name the same resource as "/path".
        request_host = ""
        if m_abs := re.match(r"(?i)^https?://([^/?#]*)(.*)$", target):
            request_host, target = m_abs.group(1), m_abs.group(2) or "/"
        status = int(m.group("status"))
        size = m.group("bytes")
        user = m.group("user")
        ua = _unescape(m.group("ua") or "")
        line_id = hashlib.sha1(line.encode("utf-8", "replace")).hexdigest()[:16]
        return Event(
            ts=ts, source=self.name, kind=EventKind.HTTP,
            dedup_key=Event.make_dedup_key(self.name, server.name, path, n, line_id),
            action=str(status), program=(method or "-")[:128], domain=site[:255],
            device=server.name, pkt_len=None if size == "-" else int(size),
            user=None if user == "-" else user[:255],
            user_agent=ua[:255] or None,
            message=f"{method} {target}".strip()[:1000],
            raw={"server": server.name, "site": site, "path": target[:1000],
                 **({"request_host": request_host[:255]} if request_host else {}),
                 "protocol": protocol[:16], "status": status,
                 "referer": _unescape(m.group("ref") or "")[:500], "file": path},
            **self.assign_zones(src_ip=m.group("ip"), dst_ip=server.ip or None),
        )

    # ----- probes ----------------------------------------------------------- #

    def self_test(self, ctx: RunContext) -> list[Probe]:
        probes: list[Probe] = []
        for server in self.servers():
            code, out, err = self._run(server, "echo dawnpatrol-ok; id -nG")
            if code != 0 or "dawnpatrol-ok" not in out:
                probes.append(Probe(name=f"{server.name}-ssh", request=f"ssh {server.host}",
                                    ok=False, detail=_first_line(err, code)))
                continue
            groups = out.split("dawnpatrol-ok", 1)[1].strip()
            probes.append(Probe(name=f"{server.name}-ssh", request=f"ssh {server.host}",
                                ok=True, detail=f"groups: {groups}"))
            if server.journal:
                code, out, err = self._run(server, "journalctl -n 1 -o json --no-pager")
                ok = code == 0 and out.strip().startswith("{")
                probes.append(Probe(name=f"{server.name}-journal", request="journalctl -n 1",
                                    ok=ok, records=1 if ok else 0,
                                    detail="" if ok else _first_line(err, code)
                                    or "no entries readable (is the account in "
                                       "systemd-journal or adm?)"))
            if server.http_roots:
                code, out, _err = self._run(server, server.find_command(limit=500))
                found, denied = _parse_listing(out)
                probes.append(Probe(
                    name=f"{server.name}-http-logs", request=f"find {server.http_roots}",
                    ok=bool(found), records=len(found),
                    detail=(", ".join(sorted({site_for(f, server.http_roots) for f in found}))
                            or "no access logs found (check HTTP_ROOTS, HTTP_PATTERN, "
                               "HTTP_FOLLOW_SYMLINKS, permissions)")
                    + (f"; unreadable: {'; '.join(denied[:3])}" if denied else "")))
        return probes


# ----- helpers ------------------------------------------------------------- #

def site_for(path: str, roots: list[str]) -> str:
    """The site a log file belongs to, from where it sits under its root.

    ``<root>/<site>/.../access.log`` -> ``<site>`` (one folder per site, e.g.
    /var/www/shop.example.com/logs/access.log); a file directly in the root is
    named for itself with the access/log suffixes removed
    (/var/log/nginx/shop.example.com.access.log -> shop.example.com), and
    nginx's own ``access.log`` -> ``default``.
    """
    root = max((r for r in roots if path == r or path.startswith(r.rstrip("/") + "/")),
               key=len, default="")
    rel = path[len(root):].lstrip("/") if root else path.rsplit("/", 1)[-1]
    parts = rel.split("/")
    if len(parts) > 1:
        return parts[0]
    name = _LOG_SUFFIX.sub("", parts[0])
    return name or "default"


def _parse_listing(out: str) -> tuple[list[str], list[str]]:
    """``find_command`` output -> (log file paths, unreadable-location messages)."""
    files, denied = [], []
    for row in out.splitlines():
        if row.startswith("! "):
            denied.append(row[2:].strip()[:200])
            continue
        _size, _, path = row.partition(" ")
        if path:
            files.append(path)
    return files, denied


def _unescape(text: str) -> str:
    """nginx escapes quotes and non-printables as \\" and \\xHH."""
    text = text.replace('\\"', '"')
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text)


def _first_line(err: str, code: int) -> str:
    line = next((x.strip() for x in (err or "").splitlines() if x.strip()), "")
    return f"exit {code}: {line}"[:300] if line else f"exit {code}"
