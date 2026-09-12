"""Domain reputation via ismalicious.com.

One upstream field is deliberately demoted. ``classification.primary`` is
derived from low-reliability indicators and returns confident-looking verdicts
("phishing" at 93% confidence) for plainly benign, long-established domains. The
verdict here is anchored on ``malicious``, ``riskScore``, and ``evidence``;
``classification.primary`` is surfaced only as an unverified hypothesis, and
only when provider agreement supports it.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import httpx

from ..models import Enrichment, Verdict
from ..secrets import read_secret
from .base import Enricher

log = logging.getLogger(__name__)

API_URL = "https://api.ismalicious.com/check"


class IsMaliciousEnricher(Enricher):
    name = "ismalicious"
    subject_types = frozenset({"domain"})
    requires_env = frozenset({"DAWNPATROL_ENRICH_ISMALICIOUS_KEY"})
    default_budget = 15
    cache_ttl = timedelta(days=3)
    batch_size = 1

    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        key = read_secret("DAWNPATROL_ENRICH_ISMALICIOUS_KEY").get()
        out: dict[str, Enrichment] = {}
        if not key:
            return {s: Enrichment(subject=s, enricher=self.name, error="no API key")
                    for s in subjects}

        with httpx.Client(timeout=25.0, headers={"X-API-KEY": key}) as client:
            for subject in subjects:
                try:
                    resp = client.get(API_URL, params={"query": subject})
                    if resp.status_code == 429:
                        out[subject] = Enrichment(subject=subject, enricher=self.name,
                                                  error="rate limited (HTTP 429)")
                        continue
                    resp.raise_for_status()
                    data = resp.json() or {}
                except Exception as exc:  # noqa: BLE001
                    out[subject] = Enrichment(subject=subject, enricher=self.name,
                                              error=f"{type(exc).__name__}: {exc}"[:200])
                    continue

                risk = data.get("riskScore") or {}
                score = risk.get("score")
                score = int(score) if isinstance(score, (int, float)) else None
                level = str(risk.get("level") or "").lower()
                malicious = bool(data.get("malicious"))
                evidence = data.get("evidence") or {}
                trust = (data.get("dataTrust") or {}).get("providerAgreement") or {}
                agreement = str(trust.get("status") or "").lower()

                attributes = {
                    "risk_level": level or None,
                    "blocklist_hits": (data.get("blocklistHits")
                                       or data.get("blocklists", {}).get("hits")),
                    "blocklist_listed": data.get("blocklistListed"),
                    "recommended_action": evidence.get("recommendedAction"),
                    "provider_agreement": agreement or None,
                    "created": ((data.get("whois") or {}).get("domain") or {}).get("created_date"),
                }

                classification = (data.get("classification") or {}).get("primary")
                if classification and agreement == "agreement" and data.get("blocklistListed"):
                    attributes["classification_hypothesis"] = classification
                elif classification:
                    attributes["classification_hypothesis"] = (
                        f"{classification} (UNVERIFIED - provider disagreement or no "
                        f"blocklist corroboration; do not report as fact)"
                    )

                out[subject] = Enrichment(
                    subject=subject,
                    enricher=self.name,
                    found=True,
                    score=score,
                    verdict=_verdict(malicious, level, score),
                    whitelisted=False,
                    categories=[c for c in (evidence.get("reasons") or [])][:5],
                    attributes=attributes,
                    raw=data,
                )
        return out

    def prefilter(self, subjects: list[str]) -> list[str]:
        """Skip known-good domains; they return no risk and waste the budget."""
        seen: set[str] = set()
        keep: list[str] = []
        for s in subjects:
            d = (s or "").strip().lower().rstrip(".")
            if not d or d in seen or "." not in d:
                continue
            if self.profile.is_benign_domain(d):
                continue
            seen.add(d)
            keep.append(d)
        return keep


def _verdict(malicious: bool, level: str, score: int | None) -> Verdict:
    if malicious or level == "critical":
        return Verdict.MALICIOUS
    if level == "high":
        return Verdict.SUSPICIOUS
    if level == "medium":
        return Verdict.UNKNOWN
    if level == "low" or (score is not None and score < 25):
        return Verdict.BENIGN
    return Verdict.UNKNOWN
