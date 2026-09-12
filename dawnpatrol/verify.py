"""Source health classification.

The distinction this module exists to protect: an empty result is not an outage.
It is more often a malformed query. A source that returns nothing gets its probes
run automatically, and only probe evidence can move it from SUSPECT to FAILED.

That is what stops the pipeline reporting "monitoring is blind" on the strength
of a date-format bug - a failure mode that discards real security data and is as
damaging as a fabricated finding.
"""

from __future__ import annotations

import logging

from .context import RunContext
from .models import CollectionResult, HealthState, SourceHealth
from .sources.base import Source

log = logging.getLogger(__name__)

#: Unique-vs-reported tolerance. Syslog is ingested live, so `total` drifts
#: upward between pages; a small shortfall is expected, not a defect.
COUNT_TOLERANCE = 0.02
SPAN_TOLERANCE = 0.15


def classify(source: Source, result: CollectionResult, ctx: RunContext) -> SourceHealth:
    requested = (result.requested_window or ctx.window)
    effective = result.window or requested

    health = SourceHealth(
        source=result.source,
        state=HealthState.OK,
        records=result.count,
        unique_records=result.unique_count,
        reported_total=result.reported_total,
        span_hours=result.span_hours,
        requested_hours=requested.hours,
        pages=result.pages,
        notes=list(result.notes),
    )

    if result.errors:
        health.notes.extend(f"error: {e}" for e in result.errors)

    # --- zero records: probe before concluding anything ---------------------- #
    if result.count == 0:
        try:
            health.probes = source.self_test(ctx)
        except Exception as exc:  # noqa: BLE001 - a failed probe is itself evidence
            log.warning("self_test for %s raised: %s", source.name, exc)
            health.notes.append(f"self_test raised {type(exc).__name__}: {exc}")

        if _probes_prove_failure(health):
            health.state = HealthState.FAILED
            health.notes.append(
                "zero records AND probes returned nothing: a genuine feed failure. "
                "Affected sections have no data."
            )
        else:
            health.state = HealthState.SUSPECT
            health.notes.append(
                "collection returned zero records; cause not established. Probes "
                "were inconclusive or contradicted an outage. This is NOT evidence "
                "that the source stopped reporting."
            )
        return health

    # --- integrity gates ------------------------------------------------------ #
    problems: list[str] = []

    if result.reported_total:
        shortfall = (result.reported_total - result.unique_count) / result.reported_total
        if shortfall > COUNT_TOLERANCE:
            problems.append(
                f"retrieved {result.unique_count} unique records against a reported "
                f"total of {result.reported_total} ({shortfall * 100:.1f}% short): "
                f"the pull is incomplete"
            )

    if result.count != result.unique_count:
        problems.append(
            f"{result.count} records contain only {result.unique_count} unique keys: "
            f"pages were duplicated"
        )

    if not result.complete:
        problems.append("pagination did not run to completion")

    # Coverage is judged against the EFFECTIVE window. A source with a known
    # retention ceiling has not fallen short of anything.
    expected_hours = effective.hours
    if expected_hours > 0 and result.span_hours < expected_hours * (1 - SPAN_TOLERANCE):
        problems.append(
            f"timestamps span {result.span_hours:.2f}h of an expected "
            f"{expected_hours:.2f}h: the pull is truncated"
        )

    if source.min_expected_records and result.count < source.min_expected_records:
        problems.append(
            f"{result.count} records is far below the configured floor of "
            f"{source.min_expected_records}: treat as a collection defect until "
            f"proven otherwise"
        )

    if result.clamped:
        health.notes.append(
            f"window clamped from {requested.hours:.0f}h to {effective.hours:.2f}h "
            f"by this source's retention. A known limit, not a shortfall - do not "
            f"extrapolate these counts to the full requested window."
        )

    health.notes.extend(source.extra_health_notes(result))

    if problems:
        health.state = HealthState.DEGRADED
        health.notes.extend(problems)
        health.notes.append(
            "a partial dataset is not a sample: percentages computed from it are "
            "wrong in a way that looks plausible"
        )
    elif result.clamped or result.errors:
        health.state = HealthState.DEGRADED

    return health


def _probes_prove_failure(health: SourceHealth) -> bool:
    """Only affirmative probe evidence justifies FAILED.

    If any probe returned data, the fault is in the request, not the feed. If no
    probes ran at all, we cannot conclude failure - that stays SUSPECT.
    """
    if not health.probes:
        return False
    if any(p.ok and (p.records or 0) > 0 for p in health.probes):
        return False
    if any(p.status == 401 for p in health.probes):
        # Authentication is a configuration fault, never an outage.
        health.notes.append(
            "a probe returned HTTP 401: the request lacked valid credentials. "
            "This is a configuration fault, not a source outage."
        )
        return False
    return all((p.records or 0) == 0 for p in health.probes)


def usable_sources(health: list[SourceHealth]) -> list[str]:
    return [h.source for h in health if h.usable]


def summarize(health: list[SourceHealth]) -> str:
    if not health:
        return "no sources ran"
    return ", ".join(f"{h.source} {h.state}" for h in health)
