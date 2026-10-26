"""JSON schema for the agent's terminal ``submit_analysis`` tool.

The model produces judgment and prose fragments. It never produces headings,
never produces the report envelope, and never produces a number that belongs to
a metric - those are rendered from analyzer output. That is what makes "every
number in the report traces to code" a property of the system rather than a rule
the model is asked to follow.
"""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SUSPECTED"]
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
        "severity": {
            "type": "string", "enum": SEVERITIES,
            "description": (
                "SUSPECTED for a finding that cites only event_ids. It is not a "
                "rating: without a signal there is nothing to rate against, and "
                "the adjudicator records any event-only finding as SUSPECTED."
            ),
        },
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
            "type": "array", "items": {"type": "string"},
            "description": (
                "Ids of the analyzer signals this finding rests on. Cite at least "
                "one whenever a signal covers the activity."
            ),
        },
        "event_ids": {
            "type": "array", "maxItems": 20, "items": {"type": "integer"},
            "description": (
                "Ids of specific events from this run (the events table's `id` "
                "column) that show the activity. Use these when no signal covers "
                "it. A finding citing neither a known signal nor a real event of "
                "this run is rejected."
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
        "detection_gaps": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["what"],
                "properties": {
                    "what": {"type": "string",
                             "description": "The activity no signal covered."},
                    "suggestion": {"type": "string",
                                   "description": "What parser or analyzer would have caught it."},
                    "event_ids": {"type": "array", "maxItems": 20,
                                  "items": {"type": "integer"}},
                },
            },
            "description": (
                "Activity worth detecting that no analyzer turned into a signal, "
                "for example log lines left unparsed or a pattern no analyzer "
                "looks for. Every SUSPECTED finding implies one. These tell the "
                "operator what detection to add, so be specific."
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


#: Problems listed back to the model; the rest are summarised as a count.
MAX_PROBLEMS = 15

_validator: Draft202012Validator | None = None


def analysis_problems(data: Any) -> list[str]:
    """Every way ``data`` departs from ANALYSIS_SCHEMA, as readable lines.

    An empty list means the analysis matches the schema exactly, which is what
    lets the adjudicator read it without defending against every shape a
    weaker model might invent.
    """
    global _validator
    if _validator is None:
        _validator = Draft202012Validator(ANALYSIS_SCHEMA)
    problems = []
    for error in sorted(_validator.iter_errors(data), key=lambda e: list(e.path)):
        where = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.path)
        problems.append(f"{where.lstrip('.') or 'top level'}: {error.message}")
    return problems


def format_correction(problems: list[str]) -> str:
    """The follow-up sent to a model whose analysis did not match the schema."""
    listed = problems[:MAX_PROBLEMS]
    more = len(problems) - len(listed)
    lines = "\n".join(f"- {p}" for p in listed)
    if more > 0:
        lines += f"\n- ...and {more} more"
    return (
        "Your analysis was NOT accepted because it does not match the required "
        "format:\n"
        f"{lines}\n\n"
        "Call submit_analysis again with your complete analysis. Make sure the "
        "arguments match exactly this JSON schema - every object must have the "
        "listed properties with the listed types, and no other properties. For "
        "example, each recommended_actions entry is an object such as "
        '{"priority": 1, "text": "..."}, not a plain string.\n\n'
        f"{json.dumps(ANALYSIS_SCHEMA, indent=1)}"
    )
