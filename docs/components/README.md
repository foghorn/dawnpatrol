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

Two commands make plugin development fast and free:

```bash
dawnpatrol run --stop-after analyze   # full pipeline, no model call, no cost
dawnpatrol run --from-run <run_id>    # re-analyze events already on disk, no re-collection
```

The first gets you a real evidence bundle - metrics, signals, source health - without
spending a cent, which is the right way to develop and sanity-check an analyzer, a new
canary, or a new source's normalizer. The second lets you iterate against a captured
day without re-pulling hundreds of thousands of records or hammering an upstream API.

Every guide below ends with a "wire it up and test it" section that assumes you're using
one or both of these.
