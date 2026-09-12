Analyse this run and submit your findings.

Work in this order:

1. Read source health first. A degraded or suspect source changes what you can
   conclude, and it belongs in `data_quality_notes` regardless of what else you
   find.
2. Read the signals. They are ordered by severity hint - a deterministic prior,
   not a verdict. You may raise or lower it with justification.
3. Group related signals. Two signals about one host are usually one finding.
4. Investigate the ones that matter with your tools. Prefer depth on a few over
   a shallow pass across all.
5. Enrich only after you have classified behaviourally, and only where it could
   change a decision.
6. Decide what the reader should actually do.

Then call `submit_analysis`.
