"""Login sessions, form tokens and login throttling for the web console.

* Sessions are a signed cookie: ``<expiry>.<nonce>.<hmac>``. The signing key is
  random per process, so restarting the console signs everyone out - fine for
  a single-operator tool, and nothing to store or leak.
* Every state-changing request is a POST carrying a form token that must match
  the ``dp_csrf`` cookie, and its ``Origin`` (when sent) must be this host.
  That holds with or without a password: without it, any web page you visit
  could make your browser start runs on the console.
* Five failed logins from one address within 15 minutes lock that address
  out for 15 minutes.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

SESSION_COOKIE = "dp_session"
CSRF_COOKIE = "dp_csrf"
MAX_FAILURES = 5
FAILURE_WINDOW = 15 * 60


class Sessions:
    def __init__(self, hours: int = 12) -> None:
        self._key = secrets.token_bytes(32)
        self.ttl = max(1, hours) * 3600

    def issue(self, now: float | None = None) -> str:
        expiry = int((now or time.time()) + self.ttl)
        body = f"{expiry}.{secrets.token_urlsafe(12)}"
        return f"{body}.{self._sign(body)}"

    def valid(self, cookie: str | None, now: float | None = None) -> bool:
        if not cookie or cookie.count(".") != 2:
            return False
        body, _, sig = cookie.rpartition(".")
        if not hmac.compare_digest(sig, self._sign(body)):
            return False
        try:
            return int(body.split(".", 1)[0]) > (now or time.time())
        except ValueError:
            return False

    def _sign(self, body: str) -> str:
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()


class LoginThrottle:
    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def locked(self, client: str, now: float | None = None) -> bool:
        now = now or time.time()
        q = self._failures[client]
        while q and now - q[0] > FAILURE_WINDOW:
            q.popleft()
        return len(q) >= MAX_FAILURES

    def failed(self, client: str, now: float | None = None) -> None:
        self._failures[client].append(now or time.time())

    def succeeded(self, client: str) -> None:
        self._failures.pop(client, None)


def password_ok(supplied: str, expected: str) -> bool:
    return bool(expected) and hmac.compare_digest(
        hashlib.sha256(supplied.encode()).digest(), hashlib.sha256(expected.encode()).digest())


def new_csrf() -> str:
    return secrets.token_urlsafe(24)


def same_origin(origin: str | None, host: str | None) -> bool:
    """A missing Origin is allowed (older browsers, same-origin GET-turned-POST
    redirects); a present one must name this host."""
    if not origin:
        return True
    if origin == "null" or not host:
        return False
    return urlsplit(origin).netloc.lower() == host.lower()
