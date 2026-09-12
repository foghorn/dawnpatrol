"""Template for a new enrichment source. Copy, rename, edit.

The framework handles caching, budget, and prefilter enforcement. Your job is
the API call and the mapping into the normalized Enrichment shape.

Deliberately normalize *away* misleading fields. If an upstream exposes a raw
counter that does not track its own verdict (AbuseIPDB's ``totalReports`` is the
canonical example), keep it in ``raw`` and leave it out of ``attributes`` - the
model cannot misreport a number it is never handed.
"""

from __future__ import annotations

from datetime import timedelta

import httpx

from ..models import Enrichment, Verdict
from ..secrets import read_secret
from .base import Enricher


class TemplateEnricher(Enricher):
    name = "template"
    subject_types = frozenset({"ip"})
    requires_env = frozenset({"DAWNPATROL_ENRICH_TEMPLATE_KEY"})
    default_budget = 25
    cache_ttl = timedelta(days=7)
    batch_size = 1

    def lookup(self, subjects: list[str]) -> dict[str, Enrichment]:
        key = read_secret("DAWNPATROL_ENRICH_TEMPLATE_KEY").get()
        out: dict[str, Enrichment] = {}
        with httpx.Client(timeout=20.0) as client:
            for subject in subjects:
                try:
                    resp = client.get(
                        "https://example.invalid/api/check",
                        params={"q": subject},
                        headers={"X-API-Key": key},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:  # noqa: BLE001 - a failed lookup is never fatal
                    out[subject] = Enrichment(subject=subject, enricher=self.name,
                                              error=str(exc)[:200])
                    continue
                score = int(data.get("score", 0))
                out[subject] = Enrichment(
                    subject=subject,
                    enricher=self.name,
                    found=True,
                    score=score,
                    verdict=Verdict.MALICIOUS if score >= 80 else Verdict.UNKNOWN,
                    attributes={"isp": data.get("isp")},
                    raw=data,
                )
        return out

    def prefilter(self, subjects: list[str]) -> list[str]:
        return [s for s in subjects if self.profile.is_routable(s)]
