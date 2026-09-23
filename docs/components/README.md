# Component guides

DawnPatrol is built from five plugin folders plus three cross-cutting systems. Each has
its own guide here: what the contract is, how the framework uses it, a walkthrough of
what actually ships, and a worked example of building your own. `docs/ARCHITECTURE.md`
is the systems-level view of how these fit together; start here if you want to build
something and start there if you want to understand why it's shaped the way it is.

| Guide | Answers |
|---|---|
| [Sources](sources.md) | How does telemetry get in? How do I add a new one? |
| [Analyzers](analyzers.md) | How do 300,000 events become a few dozen signals? How do I detect a new pattern? |
| [Signal catalog](signals.md) | What does every signal currently emitted actually mean - severity, confidence, evidence, exact trigger? |
| [Enrichment](enrichment.md) | How does an IP or domain get external context, safely and on a budget? |
| [Outputs](outputs.md) | How does a finished report get delivered? How do I add a destination? |
| [Providers](providers.md) | Which model actually does the judgment, and how do I point at a different one? |
| [Canaries](canaries.md) | How does the pipeline prove it is still detecting anything at all? |
| [Network profile](profile.md) | How does `profile.yml` turn a raw IP into "IoT segment, untrusted, behind a NAT gateway"? |
| [MCP server](mcp-server.md) | How does an external agent read reports, trigger analysis on demand, and leave notes that shape future runs? |

## The shape all five plugin folders share

Every source, analyzer, enricher, output, and provider is discovered the same way
(`registry.discover`, walking the package directory, skipping `TEMPLATE.py` and anything
starting with `_`), and every one auto-enables the same way: declare the environment
variables you need in `requires_env`, and the plugin turns on the moment they're all
present - no registration list to edit, no core file to touch. `dawnpatrol list-plugins`
shows you what was discovered and, for anything disabled, exactly which variable it's
still waiting on.

That symmetry is deliberate. If you've built one plugin type, the shape of the next one
will already look familiar.

## Before you start

Two commands make plugin development fast and disposable:

```bash
dawnpatrol run --stop-after analyze   # full pipeline, no model call, no cost
dawnpatrol run --ephemeral            # full pipeline for real, no leftover rows or files
```

The first gets you a real evidence bundle - metrics, signals, source health - without
spending a cent, which is the right way to develop and sanity-check an analyzer, a new
canary, or a new source's normalizer. The second is for iterating past that point,
against a real model call: it runs and delivers for real (add `--dry-run` too to also
skip delivery), then deletes that run's own database rows and report files once it
finishes, so repeated test runs don't pile up months of throwaway history on disk. Delete
one after the fact instead with `dawnpatrol delete-run <run_id>`. Neither touches the
`entities` baseline table that [Analyzers](analyzers.md) reads via `baseline.novel()` -
it isn't scoped to a run, and gets updated before that run's own analysis even runs, so
a test run's contribution to it can't be cleanly undone.

Every guide below ends with a "wire it up and test it" section that assumes you're using
one or both of these.
