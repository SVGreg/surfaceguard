# Corpus sweeps

Each file here is one **sweep**: a fresh slice of real Agent Skills pulled from a public source,
scanned with the built-in rule packs and no policy, then mined for what it says about the scanner.
`sg-corpus-sweep` produces them, one per maintenance cycle that lands on it.

Sweeps exist because the vendored corpora under `evaluation/` are a *baseline*, not a picture of the
present. They are fetched once and pinned, which makes them excellent for proving a rule change did
not regress and useless for noticing that the population moved. Publishers churn, install rankings
turn over, and new idioms — benign and hostile — appear between snapshots. A sweep is the periodic
re-measurement; the diff between two sweeps of the same source is the part worth reading.

## What a sweep report contains

| Section | Content |
|---|---|
| Fetched | source, bundle count, UTC date, what the fetcher skipped |
| Results | verdict mix, risk-tier spread, top rules by hit rate |
| Diff | `sweep_diff.py` against the previous sweep of the same source, or "baseline" |
| A — false positives | rule hit clusters with repeated excerpts, and the systematic cause behind each |
| B — true-positive candidates | bundles with critical/high findings, judged from findings alone |
| C — probable misses | clean bundles carrying a risky primitive (`sweep_gaps.py`), each a question |
| Filed | issue numbers and `docs/planned-rules.md` rows this sweep produced |

## What a sweep report never contains

Fetched bundle content. Reports carry counts, rule ids, bundle slugs, file paths and **escaped**
excerpts (`sweep_gaps.py` renders control bytes, bidi marks and homoglyphs as literal `\x..`;
finding excerpts are already truncated and secret-redacted by the scanner). The samples themselves
live in a quarantine directory outside the repo for the length of one cycle and are deleted before
the report ships — they are third-party content of mixed licence and unknown intent, and nothing is
gained by keeping them.

## Reading one honestly

Every hit on an unlabeled real-world corpus is a false-positive candidate until a human reads it,
and a `pass` is not a safety guarantee. Static analysis reports **capability and pattern, not
confirmed intent**: a red-team skill teaching an attack and a skill committing it are frequently the
same bytes. Section B is a list of things to look at, never an accusation.
