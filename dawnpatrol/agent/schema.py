"""JSON schema for the agent's terminal ``submit_analysis`` tool.

The model produces judgment and prose fragments. It never produces headings,
never produces the report envelope, and never produces a number that belongs to
a metric - those are rendered from analyzer output. That is what makes "every
number in the report traces to code" a property of the system rather than a rule
the model is asked to follow.
"""

from __future__ import annotations

from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CONFIDENCES = ["high", "medium", "low"]
EVIDENCE_KINDS = ["local_behavior", "baseline_delta", "correlation",
                  "reputation", "policy_violation"]
TREND_KINDS = ["NEW", "RECURRING", "ESCALATING", "RESOLVED"]

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "severity", "confidence", "taxonomy",
                 "signal_ids", "evidence_kinds", "what", "action"],
    "properties": {
        "title": {
            "type": "string", "maxLength": 120,
            "description": "One line naming the specific thing observed.",
        },
        "severity": {"type": "string", "enum": SEVERITIES},
        "confidence": {"type": "string", "enum": CONFIDENCES},
        "taxonomy": {
            "type": "string",
            "description": "Reuse the taxonomy of the signal(s) this cites.",
        },
        "zone": {
            "type": "string",
            "description": "Zone name from the site profile, or 'perimeter'.",
        },
        "signal_ids": {
            "type": "array", "minItems": 1, "items": {"type": "string"},
            "description": (
                "REQUIRED. Ids of the analyzer signals this finding rests on. A "
                "finding citing no signal is rejected - there is no path to "
                "reporting something the deterministic layer did not observe."
            ),
        },
        "evidence_kinds": {
            "type": "array", "minItems": 1,
            "items": {"type": "string", "enum": EVIDENCE_KINDS},
            "description": (
                "What kinds of evidence support this. 'reputation' alone is "
                "rejected: external context corroborates local behaviour, it "
                "never substitutes for it."
            ),
        },
        "what": {
            "type": "string",
            "description": "The observation, with the numbers that justify it.",
        },
        "why": {
            "type": "string",
            "description": "Why this shape means what you say it means.",
        },
        "not_this": {
            "type": "string",
            "description": (
                "The benign explanation you ruled out, and what ruled it out. "
                "Required for MEDIUM and above."
            ),
        },
        "action": {
            "type": "string",
            "description": "What the reader should do. 'No action needed' is valid.",
        },
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type", "value"],
                "properties": {
                    "type": {"type": "string",
                             "enum": ["ip", "domain", "host", "port", "device", "user"]},
                    "value": {"type": "string"},
                    "role": {"type": "string"},
                },
            },
        },
    },
}

ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["executive_summary", "findings", "recommended_actions"],
    "properties": {
        "executive_summary": {
            "type": "string", "maxLength": 900,
            "description": (
                "Two or three sentences of plain English. Lead with whether "
                "anything needs doing today. 'Nothing happened' is a good answer "
                "when it is true."
            ),
        },
        "findings": {
            "type": "array", "items": FINDING_SCHEMA,
            "description": "Empty array when there is genuinely nothing to report.",
        },
        "section_narratives": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "perimeter": {"type": "string"},
                "dns": {"type": "string"},
                "router": {"type": "string"},
                "segments": {"type": "string"},
                "correlation": {"type": "string"},
            },
            "description": (
                "Short interpretive prose per section. Do not restate the "
                "statistics - they are rendered from the analyzers. Say what they "
                "mean."
            ),
        },
        "trend_notes": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "text"],
                "properties": {
                    "kind": {"type": "string", "enum": TREND_KINDS},
                    "text": {"type": "string"},
                    "signal_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["priority", "text"],
                "properties": {
                    "priority": {"type": "integer", "minimum": 1, "maximum": 20},
                    "text": {"type": "string"},
                    "command": {"type": "string",
                                "description": "A concrete rule or command, when one applies."},
                },
            },
        },
        "watchlist_updates": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["entity_type", "entity_value", "reason"],
                "properties": {
                    "entity_type": {"type": "string", "enum": ["ip", "domain", "host"]},
                    "entity_value": {"type": "string"},
                    "reason": {"type": "string"},
                    "expires_days": {"type": "integer", "minimum": 1, "maximum": 365},
                },
            },
            "description": (
                "Things to carry into tomorrow's run for follow-up. Re-adding an "
                "entity already on the watchlist refreshes its expiry rather than "
                "duplicating it."
            ),
        },
        "watchlist_removals": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["entity_type", "entity_value"],
                "properties": {
                    "entity_type": {"type": "string", "enum": ["ip", "domain", "host"]},
                    "entity_value": {"type": "string"},
                    "reason": {"type": "string",
                               "description": "Why this is resolved, e.g. explained, expected, or stale."},
                },
            },
            "description": (
                "Watchlist entries to close now because they were resolved this run - "
                "explained, expected, or no longer relevant. Prefer closing an item "
                "explicitly over letting it recur silently until it expires."
            ),
        },
        "data_quality_notes": {
            "type": "array", "items": {"type": "string"},
            "description": (
                "Anything that limited the analysis. State uncertainty plainly; "
                "an empty result is not evidence of absence."
            ),
        },
    },
}
