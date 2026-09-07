#!/usr/bin/env python3
"""Diff two aggregate.py stats files — what changed between two corpus sweeps.

A sweep is only informative against a baseline: a rule producing 3 findings per
100 bundles in one snapshot and 40 in the next has either widened or met a new
idiom, and that delta is the thing worth reading. Everything is normalized per
100 bundles, so two sweeps of different sizes stay comparable.

Note that `rule_hits` in a stats file counts *findings*, not bundles — one
bundle can trip the same rule ten times — so the rule figures below are
"findings per 100 bundles" and can exceed 100. Verdict and clean shares are
genuine per-bundle percentages.

Usage:
    evaluation/scripts/sweep_diff.py OLD_STATS.json NEW_STATS.json
    evaluation/scripts/sweep_diff.py old.json new.json --min-delta 1.0

Both arguments are paths (absolute, or relative to evaluation/reports/).
Output is plain text, safe to paste into a sweep report.
"""
import argparse
import json
import os
import pathlib
import sys

REPORTS = pathlib.Path(__file__).resolve().parents[1] / "reports"


def load(arg):
    p = pathlib.Path(arg)
    if not p.is_file():
        p = REPORTS / arg
    if not p.is_file():
        sys.exit(f"no such stats file: {arg}")
    return json.loads(p.read_text())


def per100(hits, total):
    """Findings per 100 bundles — comparable across differently-sized sweeps."""
    return (100.0 * hits / total) if total else 0.0


def share(bundles, total):
    """Percentage of bundles — for verdicts and clean counts, which are per bundle."""
    return (100.0 * bundles / total) if total else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--min-delta", type=float, default=0.5,
                    help="hide rules whose findings-per-100-bundles moved less than this")
    a = ap.parse_args()

    old, new = load(a.old), load(a.new)
    n_old = old.get("total_skills") or 0
    n_new = new.get("total_skills") or 0

    print(f"bundles:   {n_old} -> {n_new}")
    clean_old = share(old.get("clean_skills", 0), n_old)
    clean_new = share(new.get("clean_skills", 0), n_new)
    print(f"clean:     {clean_old:.1f}% -> {clean_new:.1f}%  ({clean_new - clean_old:+.1f} pts)")

    print("\nverdicts (share of bundles)")
    for v in ("pass", "warn", "fail"):
        o = share(old.get("verdicts", {}).get(v, 0), n_old)
        n = share(new.get("verdicts", {}).get(v, 0), n_new)
        print(f"  {v:<5} {o:>6.1f}% -> {n:>6.1f}%   {n - o:+.1f}")

    oh, nh = old.get("rule_hits", {}), new.get("rule_hits", {})
    titles = dict(old.get("rule_titles", {}))
    titles.update(new.get("rule_titles", {}))

    rows = []
    for rid in sorted(set(oh) | set(nh)):
        o, n = per100(oh.get(rid, 0), n_old), per100(nh.get(rid, 0), n_new)
        rows.append((n - o, rid, oh.get(rid, 0), nh.get(rid, 0), o, n))
    rows.sort(key=lambda r: -abs(r[0]))

    print("\nrule findings per 100 bundles (a bundle can trip one rule many times)")
    shown = 0
    for delta, rid, o_hits, n_hits, o, n in rows:
        if abs(delta) < a.min_delta:
            continue
        flag = "  NEW" if not o_hits else ("  GONE" if not n_hits else "")
        print(f"  {rid:<12} {o:>6.1f} ({o_hits:>4}) -> {n:>6.1f} ({n_hits:>4})  "
              f"{delta:+7.1f}{flag}   {titles.get(rid, '')}")
        shown += 1
    if not shown:
        print(f"  (nothing moved by >= {a.min_delta} findings per 100 bundles)")


if __name__ == "__main__":
    main()
