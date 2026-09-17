"""Validate the agent's analysis into a Report, enforcing every guardrail.

Each rule the old system stated as an instruction is a validator here. The
difference matters: an instruction is followed most of the time, a validator is
followed every time, and clamps are recorded so you can see when the model tried
to over-reach.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .models import (
    Action,
    Confidence,
    Entity,
    EntityType,
    Finding,
    Report,
    Severity,
    Signal,
    Status,
    TrendNote,
    WatchlistUpdate,
)
from .profile import Profile

log = logging.getLogger(__name__)

#: Kinds of evidence that count as locally observed behaviour.
LOCAL_EVIDENCE = {"local_behavior", "baseline_delta", "correlation", "policy_violation"}

_COUNTRY_RE = re.compile(
    r"\b(russia|russian|china|chinese|iran|iranian|north korea|nigeria|romania|"
    r"ukraine|vietnam|brazil|india)\b",
    re.IGNORECASE,
)


class Adjudicator:
    def __init__(self, profile: Profile, signals: list[Signal]) -> None:
        self.profile = profile
        self.signals = {s.id: s for s in signals}
        self.rejections: list[str] = []
        self.adjustments: list[str] = []

    # ----- findings --------------------------------------------------------- #

    def build_findings(self, raw_findings: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for index, raw in enumerate(raw_findings or [], start=1):
            finding = self._build_one(raw, index)
            if finding is not None:
                findings.append(finding)
        return findings

    def _build_one(self, raw: dict[str, Any], index: int) -> Finding | None:
        title = str(raw.get("title") or "").strip()
        if not title:
            self.rejections.append(f"finding {index}: no title")
            return None

        # Rule: a finding must trace to at least one real signal.
        cited = [str(s) for s in (raw.get("signal_ids") or [])]
        valid = [s for s in cited if s in self.signals]
        if not valid:
            self.rejections.append(
                f"rejected {title!r}: cites no known analyzer signal "
                f"(cited {cited or 'nothing'}). A finding must trace to observed data."
            )
            return None
        unknown = [s for s in cited if s not in self.signals]

        evidence_kinds = [str(k) for k in (raw.get("evidence_kinds") or [])]
        if not evidence_kinds:
            evidence_kinds = ["local_behavior"]

        try:
            severity = Severity.parse(raw.get("severity", "INFO"))
        except ValueError:
            severity = Severity.INFO
        original = severity
        adjustments: list[str] = []

        # Rule: reputation alone never creates a finding.
        if not (set(evidence_kinds) & LOCAL_EVIDENCE):
            self.rejections.append(
                f"rejected {title!r}: evidence is {evidence_kinds}, with no local "
                f"behaviour. External reputation corroborates, it never substitutes."
            )
            return None

        # Rule: severity may exceed its strongest signal's hint by at most one level.
        hint = max((self.signals[s].severity_hint for s in valid), default=Severity.INFO)
        if int(severity) > int(hint) + 1:
            severity = Severity(min(4, int(hint) + 1))
            adjustments.append(
                f"severity clamped {original.label()} -> {severity.label()}: more than "
                f"one level above the strongest supporting signal ({hint.label()})"
            )

        # Rule: CRITICAL requires local evidence of compromise, not reputation.
        if severity == Severity.CRITICAL and "reputation" in evidence_kinds \
                and not (set(evidence_kinds) & LOCAL_EVIDENCE - {"baseline_delta"}):
            severity = Severity.HIGH
            adjustments.append(
                "severity lowered CRITICAL -> HIGH: CRITICAL requires local evidence "
                "of compromise, not external reputation"
            )

        why = str(raw.get("why") or "")
        # Rule: country is never a severity input.
        if _COUNTRY_RE.search(why) and severity >= Severity.MEDIUM:
            adjustments.append(
                "note: geography appears in the justification. Country is context "
                "only and was not treated as a severity input."
            )

        entities = []
        for e in (raw.get("entities") or []):
            try:
                entities.append(Entity(
                    type=EntityType(str(e.get("type", "host"))),
                    value=str(e.get("value", "")),
                    role=str(e.get("role", "")),
                ))
            except (ValueError, TypeError):
                continue
        if not entities:
            for sid in valid:
                entities.extend(self.signals[sid].entities)

        try:
            confidence = Confidence(str(raw.get("confidence", "medium")).lower())
        except ValueError:
            confidence = Confidence.MEDIUM

        if unknown:
            adjustments.append(f"dropped unknown signal id(s): {', '.join(unknown)}")

        caveat = ""
        for entity in entities:
            caveat = self.profile.attribution_caveat(entity.value)
            if caveat:
                break

        # Prefix with the finding id, not its title: a title can itself end in
        # a colon-shaped clause ("...nothing accepted"), which read next to an
        # adjustment's own colon ("dropped unknown signal id(s): ...") looked
        # like one garbled, doubled-up line rather than two distinct facts.
        self.adjustments.extend(f"F{index}: {a}" for a in adjustments)

        return Finding(
            id=f"F{index}",
            title=title,
            severity=severity,
            confidence=confidence,
            taxonomy=str(raw.get("taxonomy") or self.signals[valid[0]].taxonomy),
            zone=str(raw.get("zone") or "perimeter"),
            what=str(raw.get("what") or ""),
            why=why,
            not_this=str(raw.get("not_this") or ""),
            action=str(raw.get("action") or ""),
            signal_ids=valid,
            evidence_kinds=evidence_kinds,
            entities=entities[:10],
            adjustments=adjustments,
            attribution_caveat=caveat,
        )

    # ----- suppression -------------------------------------------------------- #

    def apply_suppressions(
        self, findings: list[Finding], suppressions: list[dict[str, Any]]
    ) -> tuple[list[Finding], list[Finding], list[int]]:
        """Split into (kept, suppressed, matched_suppression_ids).

        Suppressed findings are moved to an appendix rather than deleted, so a
        tuned-out pattern that changes character is still visible.
        """
        if not suppressions:
            return findings, [], []
        kept: list[Finding] = []
        hidden: list[Finding] = []
        matched: list[int] = []
        for finding in findings:
            hit = _first_match(finding, suppressions)
            if hit is None:
                kept.append(finding)
                continue
            finding.suppressed = True
            finding.suppressed_reason = hit.get("reason") or "suppressed"
            hidden.append(finding)
            matched.append(int(hit["id"]))
        return kept, hidden, matched

    # ----- rollup -------------------------------------------------------------- #

    @staticmethod
    def rollup(findings: list[Finding], canaries_ok: bool = True) -> Status:
        criticals = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        highs = sum(1 for f in findings if f.severity == Severity.HIGH)
        mediums = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        if criticals or highs >= 2 or not canaries_ok:
            return Status.RED
        if highs or mediums >= 3:
            return Status.AMBER
        return Status.GREEN


def _first_match(finding: Finding, suppressions: list[dict[str, Any]]) -> dict | None:
    for supp in suppressions:
        matcher = supp.get("matcher") or {}
        if not matcher:
            continue
        if (tax := matcher.get("taxonomy")) and tax != finding.taxonomy:
            continue
        if (entity := matcher.get("entity")):
            if not any(e.value == entity for e in finding.entities):
                continue
        if (pattern := matcher.get("title_contains")):
            if pattern.lower() not in finding.title.lower():
                continue
        max_sev = matcher.get("max_severity")
        if max_sev is not None:
            try:
                if finding.severity > Severity.parse(max_sev):
                    continue
            except ValueError:
                pass
        if not any(k in matcher for k in ("taxonomy", "entity", "title_contains")):
            continue
        return supp
    return None


def parse_trends(raw: list[dict[str, Any]] | None) -> list[TrendNote]:
    out = []
    for item in raw or []:
        kind = str(item.get("kind", "")).upper()
        text = str(item.get("text", "")).strip()
        if kind in {"NEW", "RECURRING", "ESCALATING", "RESOLVED"} and text:
            out.append(TrendNote(kind=kind, text=text,
                                 signal_ids=[str(s) for s in (item.get("signal_ids") or [])]))
    return out


def parse_actions(raw: list[dict[str, Any]] | None) -> list[Action]:
    out = []
    for item in raw or []:
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        try:
            priority = int(item.get("priority", 5))
        except (TypeError, ValueError):
            priority = 5
        out.append(Action(priority=priority, text=text,
                          command=str(item.get("command") or "")))
    return out


def parse_watchlist(raw: list[dict[str, Any]] | None) -> list[WatchlistUpdate]:
    out = []
    for item in raw or []:
        value = str(item.get("entity_value", "")).strip()
        if not value:
            continue
        try:
            days = int(item.get("expires_days", 7))
        except (TypeError, ValueError):
            days = 7
        out.append(WatchlistUpdate(
            entity_type=str(item.get("entity_type", "ip")),
            entity_value=value,
            reason=str(item.get("reason", "")),
            expires_days=max(1, min(365, days)),
        ))
    return out


def scan_for_secrets(report: Report, rendered: str, registry) -> list[str]:
    """Final gate before delivery. A credential in an outbound report is a breach."""
    hits = registry.scan(rendered)
    if hits:
        log.error("SECRET LEAK DETECTED in rendered report: %s", hits)
    return hits
