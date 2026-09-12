"""AbuseIPDB reputation for IP addresses.

The normalized :class:`Enrichment` deliberately omits ``totalReports`` and
``numDistinctUsers``. Those counters are heavily inflated for large cloud and
security-vendor networks and do not track the score at all - an address with
thousands of reports and a score of 0 is benign whitelisted scan infrastructure,
not a threat. They stay in ``raw`` for audit; the model is never handed them, so
the classic "reported 3,028 times for abuse" misreading is impossible here.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import httpx

from ..models import Enrichment, Verdict
from ..secrets import read_int, read_secret
from .base import Enricher

log = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher(Enricher):
    name = "abuseipdb"
    subject_types = frozenset({"ip"})
    requires_env = frozenset({"DAWNPATROL_ENRICH_ABUSEIPDB_KEY"})
    default_budget = 25
    cache_ttl = timedelta(days=7)
    batch_size = 1

    @property
    def max_age_days(self) -> int:
        # Fixed by default: report volume scales with the window, so a varying
        # window makes cross-run comparison meaningless.
        return read_int("DAWNPATROL_ENRICH_ABUSEIPDB_MAX_AGE_DAYS", 90)

    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        key = read_secret("DAWNPATROL_ENRICH_ABUSEIPDB_KEY").get()
        out: dict[str, Enrichment] = {}
        if not key:
            return {s: Enrichment(subject=s, enricher=self.name, error="no API key")
                    for s in subjects}

        headers = {"Key": key, "Accept": "application/json"}
        with httpx.Client(timeout=20.0, headers=headers) as client:
            for subject in subjects:
                try:
                    resp = client.get(API_URL, params={
                        "ipAddress": subject,
                        "maxAgeInDays": self.max_age_days,
                        "verbose": "",
                    })
                    if resp.status_code == 429:
                        out[subject] = Enrichment(subject=subject, enricher=self.name,
                                                  error="rate limited (HTTP 429)")
                        continue
                    resp.raise_for_status()
                    data = (resp.json() or {}).get("data") or {}
                except Exception as exc:  # noqa: BLE001 - never fatal
                    out[subject] = Enrichment(subject=subject, enricher=self.name,
                                              error=f"{type(exc).__name__}: {exc}"[:200])
                    continue

                score = data.get("abuseConfidenceScore")
                score = int(score) if score is not None else None
                whitelisted = bool(data.get("isWhitelisted"))
                out[subject] = Enrichment(
                    subject=subject,
                    enricher=self.name,
                    found=True,
                    score=score,
                    verdict=_verdict(score, whitelisted),
                    whitelisted=whitelisted,
                    categories=_categories(data),
                    attributes={
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "usage_type": data.get("usageType"),
                        "country": data.get("countryCode"),
                        "is_tor": bool(data.get("isTor")),
                        "last_reported": data.get("lastReportedAt"),
                        # Country is context only and is never a severity input;
                        # the adjudicator enforces that separately.
                    },
                    raw=data,
                )
        return out

    def prefilter(self, subjects: list[str]) -> list[str]:
        """Non-public addresses return nothing useful; never spend budget on them."""
        seen: set[str] = set()
        keep: list[str] = []
        for s in subjects:
            if s in seen or not self.profile.is_routable(s):
                continue
            seen.add(s)
            keep.append(s)
        return keep


def _verdict(score: int | None, whitelisted: bool) -> Verdict:
    if whitelisted:
        return Verdict.BENIGN
    if score is None:
        return Verdict.UNKNOWN
    if score >= 80:
        return Verdict.MALICIOUS
    if score >= 50:
        return Verdict.SUSPICIOUS
    if score >= 25:
        return Verdict.UNKNOWN
    return Verdict.BENIGN


def _categories(data: dict) -> list[str]:
    cats: list[str] = []
    if data.get("isTor"):
        cats.append("tor-exit")
    usage = (data.get("usageType") or "").lower()
    if "data center" in usage or "hosting" in usage:
        cats.append("datacenter")
    if "fixed line isp" in usage or "mobile" in usage:
        cats.append("residential")
    return cats
