"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime

from . import __version__
from . import analyzers as analyzers_pkg
from . import enrichment as enrichment_pkg
from . import outputs as outputs_pkg
from . import sources as sources_pkg
from .analyzers.base import Analyzer
from .config import Settings
from .context import RunContext, new_run_id
from .enrichment.base import Enricher
from .errors import ConfigError, DawnPatrolError
from .logging_setup import configure
from .models import UTC, Window
from .outputs.base import Output
from .profile import Profile
from .providers.registry import available_providers
from .registry import discover, env_satisfied
from .render import RENDERERS
from .render import render as render_with
from .runner import STOP_STAGES, Runner
from .scheduler import Scheduler, heartbeat_age_seconds
from .sources.base import Source
from .store import Store

log = logging.getLogger("dawnpatrol")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dawnpatrol",
        description="Scheduled network threat-hunting pipeline with an AI analysis harness.",
    )
    p.add_argument("--version", action="version", version=f"dawnpatrol {__version__}")
    p.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("serve", help="run the scheduler loop (default)")

    run = sub.add_parser("run", help="execute one run now")
    run.add_argument("--window-hours", type=int, default=None)
    run.add_argument("--dry-run", action="store_true",
                     help="do everything except actually deliver")
    run.add_argument("--stop-after", choices=STOP_STAGES, default="",
                     help="halt after a stage; 'analyze' costs no API spend")
    run.add_argument("--print", dest="do_print", action="store_true",
                     help="print the rendered report to stdout")
    run.add_argument("--format", default="plaintext", choices=sorted(RENDERERS))

    sub.add_parser("validate", help="check configuration and profile, then exit")
    sub.add_parser("list-plugins", help="show discovered plugins and why each is on or off")
    sub.add_parser("probe", help="run each source's self-test against the live systems")
    sub.add_parser("healthcheck", help="exit non-zero if the scheduler looks wedged")
    sub.add_parser("init-db", help="create database tables and exit")

    hunt = sub.add_parser("hunt", help="search retained history for an IOC")
    hunt.add_argument("--domain")
    hunt.add_argument("--ip")
    hunt.add_argument("--days", type=int, default=180)

    rep = sub.add_parser("render", help="re-render a stored run")
    rep.add_argument("run_id")
    rep.add_argument("--format", default="plaintext", choices=sorted(RENDERERS))

    sup = sub.add_parser("suppress", help="tune out a false positive, with an expiry")
    sup.add_argument("--taxonomy")
    sup.add_argument("--entity")
    sup.add_argument("--title-contains")
    sup.add_argument("--max-severity")
    sup.add_argument("--reason", required=True)
    sup.add_argument("--days", type=int, default=90)
    sup.add_argument("--author", default="cli")

    sub.add_parser("suppressions", help="list active suppressions")
    unsup = sub.add_parser("unsuppress", help="remove a suppression by id")
    unsup.add_argument("suppression_id", type=int)

    runs = sub.add_parser("runs", help="list recent runs")
    runs.add_argument("--limit", type=int, default=15)

    sub.add_parser("canary", help="report on the most recent detection self-test")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "serve"

    try:
        settings = Settings.from_env()
    except (ConfigError, ValueError, FileNotFoundError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure(args.log_level or settings.log_level, settings.secrets)

    try:
        return _dispatch(command, args, settings)
    except DawnPatrolError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.info("interrupted")
        return 130


def _dispatch(command: str, args: argparse.Namespace, settings: Settings) -> int:
    # Commands that need neither database nor profile.
    if command == "list-plugins":
        return cmd_list_plugins(settings)
    if command == "healthcheck":
        return cmd_healthcheck(settings)

    settings.ensure_dirs()
    profile = Profile.load(settings.profile_path)
    store = Store(settings.db, settings.retention)
    store.create_all()

    try:
        handlers = {
            "serve": cmd_serve, "run": cmd_run, "validate": cmd_validate,
            "probe": cmd_probe, "init-db": cmd_init_db, "hunt": cmd_hunt,
            "render": cmd_render, "suppress": cmd_suppress,
            "suppressions": cmd_suppressions, "unsuppress": cmd_unsuppress,
            "runs": cmd_runs, "canary": cmd_canary,
        }
        handler = handlers.get(command)
        if handler is None:
            print(f"unknown command {command!r}", file=sys.stderr)
            return 2
        return handler(settings, profile, store, args)
    finally:
        store.dispose()


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_serve(settings, profile, store, args) -> int:
    runner = Runner(settings, profile, store)

    def job() -> None:
        outcome = runner.run()
        if outcome.error:
            log.error("run error: %s", outcome.error)

    return Scheduler(settings, job).serve()


def cmd_run(settings, profile, store, args) -> int:
    runner = Runner(settings, profile, store)
    outcome = runner.run(
        window_hours=args.window_hours,
        dry_run=args.dry_run,
        stop_after=args.stop_after,
    )
    if outcome.error:
        log.error("run failed: %s", outcome.error)
        return 1
    if outcome.report and args.do_print:
        print(render_with(args.format, outcome.report))
    if outcome.report and not args.do_print and not outcome.stopped_after:
        r = outcome.report
        print(f"{r.status.value}: {r.finding_count} finding(s), "
              f"{r.canary_summary}, run {r.run_id}")
    if outcome.stopped_after == "analyze" and outcome.report:
        print(f"\n{len(outcome.report.metrics)} metrics, "
              f"{len(outcome.report.signals)} signals, no API spend.")
        for signal in sorted(outcome.report.signals,
                             key=lambda s: -int(s.severity_hint))[:15]:
            print(f"  [{signal.severity_hint.label():8}] {signal.id}: {signal.title}")
    failed = [d for d in outcome.deliveries if not d.ok]
    return 1 if failed else 0


def cmd_validate(settings, profile, store, args) -> int:
    print("configuration")
    for key, value in settings.describe().items():
        print(f"  {key:22}: {value}")
    print(f"\nprofile: {profile.site_name}")
    print(f"  zones  : {len(profile.zones)} "
          f"({', '.join(z.name for z in profile.zones) or 'none'})")
    print(f"  hosts  : {len(profile.hosts)}")
    print(f"  quirks : {len(profile.known_quirks)}")
    if not profile.zones:
        print("  WARNING: no zones defined; segment review and zone attribution "
              "will be unavailable")
    print("\ndatabase: reachable, tables present")
    providers = available_providers()
    print(f"\nproviders discovered: {', '.join(sorted(providers)) or 'none'}")
    if settings.ai.enabled:
        cls = providers.get(settings.ai.provider)
        if cls is None:
            print(f"  ERROR: configured provider {settings.ai.provider!r} not found")
            return 1
        ok, reason = cls(settings.ai).available()
        print(f"  {settings.ai.provider}: {'ready' if ok else 'NOT READY - ' + reason}")
    return 0


def cmd_list_plugins(settings: Settings) -> int:
    groups = [
        ("sources", sources_pkg, Source, "source"),
        ("analyzers", analyzers_pkg, Analyzer, "analyzer"),
        ("enrichment", enrichment_pkg, Enricher, "enricher"),
        ("outputs", outputs_pkg, Output, "output"),
    ]
    for label, package, base, kind in groups:
        print(f"\n{label}:")
        classes = discover(package, base)
        if not classes:
            print("  (none discovered)")
            continue
        for cls in classes:
            satisfied, missing = env_satisfied(getattr(cls, "requires_env", frozenset()))
            allowed = settings.allowed(kind, cls.name)
            if not allowed:
                state = "disabled (config)"
            elif satisfied:
                state = "ENABLED"
            else:
                state = f"disabled (needs {', '.join(missing)})"
            print(f"  {cls.name:22} {state}")
    print("\nproviders:")
    for name, _cls in sorted(available_providers().items()):
        marker = " <- selected" if name == settings.ai.provider else ""
        print(f"  {name:22}{marker}")
    print("\nrenderers:")
    print(f"  {', '.join(sorted(RENDERERS))}")
    return 0


def cmd_probe(settings, profile, store, args) -> int:
    runner = Runner(settings, profile, store)
    sources = runner.load_sources()
    if not sources:
        print("no sources are enabled; nothing to probe")
        return 1
    ctx = RunContext(
        run_id=new_run_id(), started_at=datetime.now(UTC),
        window=Window.ending_now(settings.window_hours),
        settings=settings, profile=profile, store=store,
    )
    failures = 0
    for source in sources:
        print(f"\n{source.name}:")
        try:
            probes = source.self_test(ctx)
        except Exception as exc:  # noqa: BLE001
            print(f"  self_test raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        if not probes:
            print("  (this source declares no probes)")
            continue
        for probe in probes:
            state = "ok  " if probe.ok else "FAIL"
            print(f"  [{state}] {probe.name:24} status={probe.status} "
                  f"records={probe.records} {probe.detail}".rstrip())
            if not probe.ok:
                failures += 1
    return 1 if failures else 0


def cmd_init_db(settings, profile, store, args) -> int:
    print(f"tables created in {settings.db.display}")
    return 0


def cmd_hunt(settings, profile, store, args) -> int:
    if not args.domain and not args.ip:
        print("supply --domain or --ip", file=sys.stderr)
        return 2
    rows = (store.hunt_domain(args.domain, args.days) if args.domain
            else store.hunt_ip(args.ip, args.days))
    target = args.domain or args.ip
    if not rows:
        print(f"no record of {target} in {args.days} days of retained history.")
        print("This is bounded by retention, and is not proof of absence.")
        return 0
    print(f"{len(rows)} record(s) for {target} in the last {args.days} days:\n")
    for row in rows:
        print("  " + "  ".join(f"{k}={v}" for k, v in row.items()))
    return 0


def cmd_render(settings, profile, store, args) -> int:
    print(f"re-rendering stored runs is not implemented yet (run {args.run_id}).",
          file=sys.stderr)
    print("The JSON report written by the 'file' output is the durable record.",
          file=sys.stderr)
    return 2


def cmd_suppress(settings, profile, store, args) -> int:
    matcher = {}
    if args.taxonomy:
        matcher["taxonomy"] = args.taxonomy
    if args.entity:
        matcher["entity"] = args.entity
    if args.title_contains:
        matcher["title_contains"] = args.title_contains
    if args.max_severity:
        matcher["max_severity"] = args.max_severity
    if not any(k in matcher for k in ("taxonomy", "entity", "title_contains")):
        print("supply at least one of --taxonomy, --entity, --title-contains",
              file=sys.stderr)
        return 2
    sid = store.add_suppression(matcher, args.reason, args.author, args.days)
    print(f"suppression {sid} created, expires in {args.days} days: {matcher}")
    print("Matching findings will be moved to the report appendix, not deleted.")
    return 0


def cmd_suppressions(settings, profile, store, args) -> int:
    rows = store.active_suppressions()
    if not rows:
        print("no active suppressions")
        return 0
    for row in rows:
        print(f"  [{row['id']}] {json.dumps(row['matcher'])}")
        print(f"       reason: {row['reason']}  expires: {row['expires']}")
    return 0


def cmd_unsuppress(settings, profile, store, args) -> int:
    if store.delete_suppression(args.suppression_id):
        print(f"suppression {args.suppression_id} removed")
        return 0
    print(f"no suppression with id {args.suppression_id}", file=sys.stderr)
    return 1


def cmd_runs(settings, profile, store, args) -> int:
    rows = store.recent_runs(args.limit)
    if not rows:
        print("no runs recorded yet")
        return 0
    print(f"{'run_id':30} {'status':7} {'find':>4} {'cost':>7}  window")
    for row in rows:
        status = row.get("status") or ("ERROR" if row.get("error") else "?")
        print(f"{row['run_id']:30} {status:7} {row.get('finding_count') or 0:>4} "
              f"{row.get('cost_usd') or 0:>7.3f}  "
              f"{row['window_start']} -> {row['window_end']}")
    return 0


def cmd_canary(settings, profile, store, args) -> int:
    runs = store.recent_runs(1)
    if not runs:
        print("no runs recorded yet")
        return 0
    from sqlalchemy import select

    from . import schema as S

    with store.engine.connect() as conn:
        rows = conn.execute(
            select(S.canaries).where(S.canaries.c.run_id == runs[0]["run_id"])
        ).mappings().all()
    if not rows:
        print(f"run {runs[0]['run_id']} recorded no canaries")
        return 0
    failures = 0
    for row in rows:
        state = "detected" if row["detected"] else "NOT DETECTED"
        print(f"  {row['canary']:22} {state}  {row['detail'] or ''}")
        if not row["detected"]:
            failures += 1
    return 1 if failures else 0


def cmd_healthcheck(settings: Settings) -> int:
    """Exit non-zero when the scheduler has stopped ticking."""
    age = heartbeat_age_seconds(settings.data_dir)
    if age is None:
        print("no heartbeat yet", file=sys.stderr)
        return 1
    if age > 900:
        print(f"heartbeat is {age:.0f}s old", file=sys.stderr)
        return 1
    print(f"ok (heartbeat {age:.0f}s old)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
