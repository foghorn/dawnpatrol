"""Pipeline orchestration.

Ten stages, of which exactly one calls a model. Every stage records its outcome,
so a failed run is debuggable from the database without re-running it - which
matters when a run costs money and takes minutes.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import analyzers as analyzers_pkg
from . import enrichment as enrichment_pkg
from . import outputs as outputs_pkg
from . import sources as sources_pkg
from .adjudicate import (
    Adjudicator,
    parse_actions,
    parse_trends,
    parse_watchlist,
    parse_watchlist_removals,
    scan_for_secrets,
)
from .agent.harness import Harness
from .analyzers.base import Analyzer
from .analyzers.baseline import Baseline
from .canary import CANARY_SOURCE, CanaryRunner
from .config import Settings
from .context import RunContext, new_run_id
from .enrichment.base import Enricher
from .enrichment.broker import EnrichmentBroker
from .models import (
    UTC,
    CollectionResult,
    DeliveryResult,
    Metric,
    Report,
    Signal,
    SourceHealth,
    Status,
    Window,
)
from .outputs.base import Output
from .profile import Profile
from .providers.registry import build_provider
from .query import EventQuery
from .registry import discover, env_satisfied
from .render import render as render_with
from .sources.base import Source
from .store import Store, entity_pairs_from_events
from .verify import classify

log = logging.getLogger(__name__)

STOP_STAGES = ["collect", "verify", "persist", "analyze", "investigate",
               "adjudicate", "render", "deliver"]


@dataclass
class RunOutcome:
    report: Report | None = None
    rendered: dict[str, str] = field(default_factory=dict)
    deliveries: list[DeliveryResult] = field(default_factory=list)
    error: str | None = None
    stopped_after: str = ""
    #: Set even when report is None (an early failure) - the one thing every
    #: outcome has, since start_run() writes the row before anything else runs.
    run_id: str = ""

    @property
    def ok(self) -> bool:
        return self.report is not None and self.error is None


class Runner:
    def __init__(self, settings: Settings, profile: Profile, store: Store) -> None:
        self.settings = settings
        self.profile = profile
        self.store = store
        self.canary = CanaryRunner(enabled=settings.canary_enabled)

    # ----- plugin loading ---------------------------------------------------- #

    def load_sources(self) -> list[Source]:
        chosen: list[Source] = []
        for cls in discover(sources_pkg, Source):
            if not self.settings.allowed("source", cls.name):
                continue
            satisfied, missing = env_satisfied(cls.requires_env)
            if not satisfied:
                log.info("source %s disabled (missing %s)", cls.name, ", ".join(missing))
                continue
            instance = cls()
            instance.configure(self.profile)
            chosen.append(instance)
        return chosen

    def load_analyzers(self) -> list[Analyzer]:
        found = [cls() for cls in discover(analyzers_pkg, Analyzer)
                 if self.settings.allowed("analyzer", cls.name)]
        return sorted(found, key=lambda a: (a.order, a.name))

    def load_enrichers(self) -> list[Enricher]:
        chosen: list[Enricher] = []
        for cls in discover(enrichment_pkg, Enricher):
            if not self.settings.allowed("enricher", cls.name):
                continue
            satisfied, missing = env_satisfied(cls.requires_env)
            if not satisfied:
                log.info("enricher %s disabled (missing %s)", cls.name, ", ".join(missing))
                continue
            chosen.append(cls())
        return chosen

    def load_outputs(self) -> list[Output]:
        chosen: list[Output] = []
        for cls in discover(outputs_pkg, Output):
            if not self.settings.allowed("output", cls.name):
                continue
            satisfied, missing = env_satisfied(cls.requires_env)
            if not satisfied:
                log.info("output %s disabled (missing %s)", cls.name, ", ".join(missing))
                continue
            instance = cls()
            instance.configure()
            chosen.append(instance)
        return chosen

    # ----- the pipeline -------------------------------------------------------- #

    def run(self, *, window_hours: int | None = None, dry_run: bool = False,
            stop_after: str = "", now: datetime | None = None,
            reuse_run_id: str | None = None, sources: list[str] | None = None,
            skip_outputs: frozenset[str] = frozenset()) -> RunOutcome:
        started = now or datetime.now(UTC)
        hours = window_hours or self.settings.window_hours
        window = Window.ending_now(hours, now=started)
        run_id = reuse_run_id or new_run_id(started)

        ctx = RunContext(
            run_id=run_id,
            started_at=started,
            window=window,
            settings=self.settings,
            profile=self.profile,
            store=self.store,
            run_number=self.store.next_run_number(),
            dry_run=dry_run,
        )
        outcome = RunOutcome(run_id=run_id)
        timings: dict[str, float] = {}

        log.info("run %s starting | window %s | %s", run_id, window,
                 "DRY RUN" if dry_run else "live")

        if reuse_run_id is None:
            self.store.start_run(run_id, ctx.run_number, started, window)

        try:
            # 1-2 COLLECT
            with _timed(timings, "collect"):
                active_sources = self.load_sources()
                if sources is not None:
                    wanted = set(sources)
                    known = {s.name for s in active_sources}
                    unknown = wanted - known
                    active_sources = [s for s in active_sources if s.name in wanted]
                    if unknown:
                        outcome.error = (
                            f"requested source(s) not enabled: {', '.join(sorted(unknown))}. "
                            f"Enabled sources: {', '.join(sorted(known)) or '(none)'}"
                        )
                        self.store.finish_run(run_id, finished_at=datetime.now(UTC),
                                              error=outcome.error)
                        return outcome
                if not active_sources:
                    outcome.error = (
                        "no sources are enabled. Set the environment variables for at "
                        "least one source plugin (see `dawnpatrol list-plugins`)."
                    )
                    self.store.finish_run(run_id, finished_at=datetime.now(UTC),
                                          error=outcome.error)
                    return outcome
                results = self._collect(active_sources, ctx)

            # 3-4 VERIFY
            with _timed(timings, "verify"):
                health: list[SourceHealth] = []
                for source, result in results:
                    h = classify(source, result, ctx)
                    health.append(h)
                    log.info("source %s: %s (%d records, %.2fh)",
                             h.source, h.state, h.records, h.span_hours)
                self.store.save_health(run_id, health)

            if stop_after == "collect":
                return self._stop(outcome, "collect", timings, run_id)

            # 5 PERSIST
            with _timed(timings, "persist"):
                events = [e for _s, r in results for e in r.events]
                kinds = {e.kind for e in events}
                canary_events = self.canary.inject(window, kinds)
                ctx.canary_entities = self.canary.entity_values()
                stored = self.store.insert_events(run_id, events + canary_events)
                self.store.observe_entities(entity_pairs_from_events(events), started)
                log.info("persisted %d events (%d real, %d canary)",
                         stored, len(events), len(canary_events))

            if stop_after == "persist":
                return self._stop(outcome, "persist", timings, run_id)

            # 6 ANALYZE
            # Real analysis excludes canary events entirely, so synthetic
            # activity can never inflate a reported statistic.
            with _timed(timings, "analyze"):
                query = EventQuery(self.store, run_id,
                                   exclude_sources={CANARY_SOURCE})
                baseline = Baseline(self.store, run_id)
                metrics, signals, notes = self._analyze(query, baseline)
                self.store.save_metrics(run_id, started, metrics)
                self.store.save_signals(run_id, signals)
                self._persist_ioc(query, run_id, started)

            # A second, tiny pass over canary events only proves the analyzer
            # chain still detects what it is designed to detect.
            canary_results = self._verify_canaries(run_id, baseline)
            self.store.save_canaries(run_id, canary_results)

            if stop_after == "analyze":
                outcome.report = self._skeleton(ctx, health, metrics, signals,
                                                canary_results, notes)
                return self._stop(outcome, "analyze", timings, run_id)

            # 7 INVESTIGATE
            with _timed(timings, "investigate"):
                analysis, harness_notes, usage = self._investigate(
                    ctx, health, metrics, signals, notes, baseline
                )

            # 8 ADJUDICATE
            with _timed(timings, "adjudicate"):
                report = self._adjudicate(
                    ctx, analysis, health, metrics, signals,
                    notes + harness_notes, canary_results, usage,
                )
                outcome.report = report
                self.store.save_findings(run_id, started,
                                         report.findings + report.suppressed_findings)
                for update in parse_watchlist((analysis or {}).get("watchlist_updates")):
                    self.store.add_watch(update.entity_type, update.entity_value,
                                         update.reason, run_id, update.expires_days)
                for removal in parse_watchlist_removals(
                    (analysis or {}).get("watchlist_removals")
                ):
                    self.store.remove_watch(removal.entity_type, removal.entity_value)

            if stop_after == "adjudicate":
                return self._stop(outcome, "adjudicate", timings, run_id)

            # 9 RENDER
            with _timed(timings, "render"):
                outputs = [o for o in self.load_outputs() if o.name not in skip_outputs]
                needed = {o.renderer for o in outputs} | {"plaintext"}
                for name in needed:
                    outcome.rendered[name] = render_with(name, report)
                leaks = scan_for_secrets(report, "\n".join(outcome.rendered.values()),
                                         self.settings.secrets)
                if leaks:
                    outcome.error = (f"delivery aborted: rendered report contains "
                                     f"configured secret value(s): {leaks}")
                    self.store.finish_run(run_id, finished_at=datetime.now(UTC),
                                          error=outcome.error)
                    return outcome

            if stop_after == "render":
                return self._stop(outcome, "render", timings, run_id)

            # 10 DELIVER
            with _timed(timings, "deliver"):
                outcome.deliveries = self._deliver(outputs, outcome.rendered, report, ctx)
                self.store.save_deliveries(run_id, outcome.deliveries)

            # 11 CHECKPOINT
            purged = self.store.purge()
            if purged:
                log.info("retention purge: %s", purged)

            self.store.finish_run(
                run_id,
                finished_at=datetime.now(UTC),
                status=report.status.value,
                finding_count=report.finding_count,
                degraded=report.degraded,
                model=self.settings.ai.model,
                provider=self.settings.ai.provider,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cache_read_tokens=usage.cache_read_tokens,
                cost_usd=usage.cost_usd,
                stages=timings,
            )
            log.info("run %s finished: %s, %d finding(s), est. $%.3f",
                     run_id, report.status.value, report.finding_count, usage.cost_usd)

        except Exception as exc:  # noqa: BLE001 - a crashed run must still be recorded
            log.exception("run %s failed", run_id)
            outcome.error = f"{type(exc).__name__}: {exc}"
            self.store.finish_run(run_id, finished_at=datetime.now(UTC),
                                  error=outcome.error, stages=timings)
        return outcome

    # ----- stages ---------------------------------------------------------------- #

    def _collect(self, sources: list[Source],
                 ctx: RunContext) -> list[tuple[Source, CollectionResult]]:
        """Sources run concurrently; each is isolated so one failure is not fatal."""
        results: list[tuple[Source, CollectionResult]] = []

        def one(source: Source) -> tuple[Source, CollectionResult]:
            try:
                return source, source.collect(ctx.window, ctx)
            except Exception as exc:  # noqa: BLE001
                log.exception("source %s raised", source.name)
                return source, CollectionResult(
                    source=source.name, requested_window=ctx.window,
                    window=source.effective_window(ctx.window),
                    errors=[f"{type(exc).__name__}: {exc}"], complete=False,
                )

        with ThreadPoolExecutor(max_workers=min(8, len(sources))) as pool:
            for pair in pool.map(one, sources):
                results.append(pair)
        return results

    def _analyze(self, query: EventQuery,
                 baseline: Baseline) -> tuple[list[Metric], list[Signal], list[str]]:
        kinds = query.kinds_present()
        sources = query.sources_present()
        metrics: list[Metric] = []
        signals: list[Signal] = []
        notes: list[str] = []
        results = []

        for analyzer in self.load_analyzers():
            if not analyzer.applicable(kinds, sources):
                log.debug("analyzer %s not applicable", analyzer.name)
                continue
            try:
                result = analyzer.run(query, self.profile, baseline)
            except Exception as exc:  # noqa: BLE001 - one bad analyzer is not fatal
                log.exception("analyzer %s raised", analyzer.name)
                notes.append(f"analyzer {analyzer.name} failed: {type(exc).__name__}: {exc}")
                continue
            results.append(result)
            metrics.extend(result.metrics)
            signals.extend(result.signals)
            notes.extend(result.notes)

        self.canary.mark_signals(results)
        prior = baseline.prior_metrics
        for metric in metrics:
            if metric.prior is None and metric.key in prior:
                metric.prior = prior[metric.key]
        log.info("analysis: %d metrics, %d signals from %d analyzers",
                 len(metrics), len(signals), len(results))
        return metrics, signals, notes

    def _verify_canaries(self, run_id: str, baseline: Baseline) -> list[Any]:
        """Run the applicable analyzers over canary events alone.

        Cheap (a few hundred synthetic rows) and completely isolated: canary
        signals never enter the report, and canary events never enter a metric.
        """
        if not self.canary.enabled or not self.canary.tokens:
            return []
        q = EventQuery(self.store, run_id, only_sources={CANARY_SOURCE})
        kinds = q.kinds_present()
        signals: list[Signal] = []
        for analyzer in self.load_analyzers():
            if not analyzer.applicable(kinds, {CANARY_SOURCE}):
                continue
            try:
                result = analyzer.run(q, self.profile, baseline)
            except Exception as exc:  # noqa: BLE001
                log.warning("analyzer %s raised during canary verification: %s",
                            analyzer.name, exc)
                continue
            for signal in result.signals:
                signal.is_canary = True
            signals.extend(result.signals)
        return self.canary.verify(signals)

    def _persist_ioc(self, query: EventQuery, run_id: str, day: datetime) -> None:
        """Narrow long-term slice: small rows, long life, retroactive hunting."""
        try:
            dns_rows = [r for r in query.dns_pairs_for_ioc() if r[1]]
            if dns_rows:
                self.store.save_ioc_dns(run_id, day, dns_rows)
            flow_rows = [r for r in query.flow_pairs_for_ioc()
                         if r[1] and self.profile.is_external(r[1])]
            if flow_rows:
                self.store.save_ioc_flow(run_id, day, flow_rows)
        except Exception as exc:  # noqa: BLE001
            log.warning("IOC slice persistence failed: %s", exc)

    def _investigate(self, ctx, health, metrics, signals, notes, baseline):
        from .models import TokenUsage

        usage = TokenUsage()
        if not self.settings.ai.enabled:
            return None, ["AI analysis is disabled; this is a statistics-only report."], usage

        enrichers = self.load_enrichers()
        broker = EnrichmentBroker(enrichers, self.store, self.profile,
                                  enabled=self.settings.enrichment_enabled)
        try:
            provider = build_provider(self.settings.ai)
        except Exception as exc:  # noqa: BLE001
            return None, [f"AI provider could not be built: {exc}"], usage

        harness = Harness(provider=provider, settings=self.settings, store=self.store,
                          profile=self.profile, broker=broker)
        result = harness.run(ctx=ctx, health=health, metrics=metrics,
                             signals=signals, notes=notes, baseline=baseline)
        extra = list(result.notes)
        extra.append(broker.stats.summary())
        if not result.ok:
            extra.append(
                f"AI analysis did not complete ({result.error}). The statistics and "
                f"signals below are unaffected; only the narrative is missing."
            )
            log.error("analysis stage failed: %s", result.error)
        return result.analysis, extra, result.usage

    def _adjudicate(self, ctx, analysis, health, metrics, signals, notes,
                    canary_results, usage) -> Report:
        adjudicator = Adjudicator(self.profile, signals)
        data = analysis or {}

        findings = adjudicator.build_findings(data.get("findings") or [])
        suppressions = self.store.active_suppressions()
        kept, hidden, matched = adjudicator.apply_suppressions(findings, suppressions)
        for suppression_id in matched:
            self.store.bump_suppression(suppression_id)

        canaries_ok = all(c.detected for c in canary_results) if canary_results else True
        status = Adjudicator.rollup(kept, canaries_ok=canaries_ok)

        quality = list(notes)
        quality.extend(str(n) for n in (data.get("data_quality_notes") or []))
        quality.extend(adjudicator.rejections)
        quality.extend(adjudicator.adjustments)
        if not canaries_ok:
            failed = [c.name for c in canary_results if not c.detected]
            quality.insert(0, (
                f"DETECTION SELF-TEST FAILED for {', '.join(failed)}. The pipeline did "
                f"not detect synthetic activity it is designed to detect. Treat this "
                f"run's GREEN/AMBER assessment as unverified and investigate the "
                f"analyzer chain."
            ))

        return Report(
            run_id=ctx.run_id,
            generated_at=ctx.started_at,
            window=ctx.window,
            status=status,
            findings=kept,
            suppressed_findings=hidden,
            metrics=metrics,
            signals=[s for s in signals if not s.is_canary],
            health=health,
            devices=ctx.devices.to_bundle(),
            executive_summary=str(data.get("executive_summary") or ""),
            section_narratives=data.get("section_narratives") or {},
            trend_notes=parse_trends(data.get("trend_notes")),
            actions=parse_actions(data.get("recommended_actions")),
            data_quality=quality,
            canaries=canary_results,
            usage=usage,
            degraded=analysis is None,
            site_name=self.profile.site_name,
        )

    def _deliver(self, outputs: list[Output], rendered: dict[str, str],
                 report: Report, ctx: RunContext) -> list[DeliveryResult]:
        results: list[DeliveryResult] = []
        for output in outputs:
            should, reason = output.should_run(report)
            if not should:
                log.info("output %s skipped: %s", output.name, reason)
                results.append(DeliveryResult(output=output.name, ok=True,
                                              skipped=True, detail=reason))
                continue
            body = rendered.get(output.renderer) or rendered["plaintext"]
            try:
                result = output.emit(body, report, ctx)
            except Exception as exc:  # noqa: BLE001
                log.exception("output %s raised", output.name)
                result = DeliveryResult(output=output.name, ok=False,
                                        detail=f"{type(exc).__name__}: {exc}"[:300])
            level = logging.INFO if result.ok else logging.ERROR
            log.log(level, "output %s: %s", output.name, result.detail)
            results.append(result)
        return results

    # ----- helpers ------------------------------------------------------------------ #

    def _skeleton(self, ctx, health, metrics, signals, canary_results, notes) -> Report:
        """Statistics-only report, for --stop-after analyze."""
        return Report(
            run_id=ctx.run_id, generated_at=ctx.started_at, window=ctx.window,
            status=Status.GREEN, metrics=metrics,
            signals=[s for s in signals if not s.is_canary],
            health=health, devices=ctx.devices.to_bundle(), canaries=canary_results,
            data_quality=list(notes), degraded=True, site_name=self.profile.site_name,
            executive_summary="Pipeline stopped before analysis (--stop-after analyze).",
        )

    def _stop(self, outcome: RunOutcome, stage: str, timings: dict[str, float],
              run_id: str) -> RunOutcome:
        outcome.stopped_after = stage
        self.store.finish_run(run_id, finished_at=datetime.now(UTC), stages=timings)
        log.info("stopped after stage '%s'", stage)
        return outcome


class _timed:
    def __init__(self, sink: dict[str, float], name: str) -> None:
        self.sink, self.name, self.start = sink, name, 0.0

    def __enter__(self) -> _timed:
        self.start = time.monotonic()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.sink[self.name] = round(time.monotonic() - self.start, 3)
        log.debug("stage %s took %.3fs", self.name, self.sink[self.name])
