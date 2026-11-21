"""Published search-engine crawler address ranges, cached in the data folder.

Google and Microsoft publish the addresses their crawlers use. A request whose
user agent says Googlebot or Bingbot from anywhere else is not that crawler:
it is a scanner wearing its name, usually to slip past bot rules that wave
search engines through (``analyzers/http_activity.py``, fake-crawler check).

Analyzers do no network I/O, so the runner calls :func:`refresh` before the
analyze stage: it downloads the lists at most once every ``MAX_AGE_DAYS`` and
keeps the last good copy if a download fails. The analyzer reads the cached
file with :func:`load`. ``DAWNPATROL_CRAWLER_RANGES=false`` turns the download
off (the check is then skipped and says so).
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from .secrets import read_bool, read_env

log = logging.getLogger(__name__)

#: claimed crawler (matched case-insensitively in the user agent) -> list URL
SOURCES = {
    "googlebot": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
}
CACHE_NAME = "crawler-ranges.json"
MAX_AGE_DAYS = 7


def cache_path(data_dir: str | Path | None = None) -> Path:
    base = data_dir or read_env("DAWNPATROL_DATA_DIR", "./data") or "./data"
    return Path(base) / CACHE_NAME


def refresh(data_dir: str | Path, *, client: httpx.Client | None = None,
            now: datetime | None = None) -> str:
    """Download the lists if the cache is missing or stale. Never raises."""
    if not read_bool("DAWNPATROL_CRAWLER_RANGES", True):
        return "disabled"
    path = cache_path(data_dir)
    now = now or datetime.now(UTC)
    cached = _read(path)
    if cached and now - _when(cached) < timedelta(days=MAX_AGE_DAYS):
        return "fresh"
    ranges: dict[str, list[str]] = {}
    own = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=True)
    try:
        for bot, url in SOURCES.items():
            try:
                resp = client.get(url)
                resp.raise_for_status()
                prefixes = [p.get("ipv4Prefix") or p.get("ipv6Prefix")
                            for p in resp.json().get("prefixes") or []]
                ranges[bot] = [str(ipaddress.ip_network(p)) for p in prefixes if p]
            except Exception as exc:  # noqa: BLE001
                log.warning("crawler ranges: %s download failed: %s", bot, exc)
    finally:
        if own:
            client.close()
    if not ranges:
        return "failed (kept previous copy)" if cached else "failed"
    merged = {**(cached or {}).get("ranges", {}), **ranges}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"fetched_at": now.isoformat(), "ranges": merged}),
                        encoding="utf-8")
    except OSError as exc:
        log.warning("crawler ranges: could not write %s: %s", path, exc)
        return "failed"
    return "updated"


def load(data_dir: str | Path | None = None) -> dict[str, list[Any]]:
    """claimed crawler -> list of ip_network, or {} when no cache exists."""
    cached = _read(cache_path(data_dir))
    out: dict[str, list[Any]] = {}
    for bot, nets in ((cached or {}).get("ranges") or {}).items():
        parsed = []
        for n in nets:
            try:
                parsed.append(ipaddress.ip_network(n))
            except ValueError:
                continue
        if parsed:
            out[bot] = parsed
    return out


def claimed_crawler(user_agent: str | None) -> str | None:
    ua = (user_agent or "").lower()
    return next((bot for bot in SOURCES if bot in ua), None)


def is_genuine(ip: str | None, bot: str, ranges: dict[str, list[Any]]) -> bool | None:
    """True/False, or None when that crawler's list isn't available."""
    nets = ranges.get(bot)
    if not nets:
        return None
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _when(cached: dict[str, Any]) -> datetime:
    try:
        return datetime.fromisoformat(cached["fetched_at"])
    except (KeyError, ValueError, TypeError):
        return datetime.min.replace(tzinfo=UTC)
