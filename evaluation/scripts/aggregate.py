#!/usr/bin/env python3
"""Aggregate evaluation/reports/raw/*.json into stats.json + REPORT.md."""
import glob
import json
import os
import pathlib
from collections import Counter, defaultdict

HERE = os.path.dirname(__file__)
RAW = os.path.join(HERE, "..", "reports", os.environ.get("RAW_DIR", "raw"))
OUT = os.path.join(HERE, "..", "reports")
REPORT_NAME = os.environ.get("REPORT_NAME", "REPORT.md")
STATS_NAME = os.environ.get("STATS_NAME", "stats.json")
TITLE = os.environ.get("REPORT_TITLE",
                       "surfaceguard — Skill Corpus Security Evaluation")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def load():
    rows = []
    for f in sorted(glob.glob(os.path.join(RAW, "*.json"))):
        d = json.load(open(f))
        rows.append(d)
    return rows


_MANIFESTS = {}


def _manifest_for(bundle, source):
    """The `_manifest.json` of the corpus dir named `source` above `bundle`, as
    {path-relative-to-that-dir: entry}. Found by walking up from the bundle, so
    it works for the vendored corpora and for a sweep quarantine alike."""
    for d in [bundle, *bundle.parents]:
        if d.name != source:
            continue
        if d not in _MANIFESTS:
            idx = {}
            mf = d / "_manifest.json"
            try:
                entries = json.loads(mf.read_text())
            except (OSError, ValueError):
                entries = []
            for e in entries if isinstance(entries, list) else []:
                if isinstance(e, dict) and e.get("dir"):
                    idx[e["dir"].split("/", 1)[-1]] = e
            _MANIFESTS[d] = idx
        return d, _MANIFESTS[d]
    return None, {}


def publisher_of(d):
    """Who published this bundle, for de-duplicating rule reach.

    Registries are full of sibling bundles from one author, so a per-bundle rate
    weights one house style by however many skills it shipped (32 of one
    sweep's 56 SG-DEP-007 hits were four sibling bundles). Each fetcher records
    the publisher under its own key: `owner` (clawhub, skillsmp), `org` (orgs,
    aws), or an `owner/repo` `source` (skillssh, anthropic). A bundle with no
    manifest entry counts as its own publisher, which degrades to the per-bundle
    figure rather than inventing a merge.
    """
    src = d.get("_source", "?")
    path = d.get("_path")
    if path:
        root, idx = _manifest_for(pathlib.Path(path), src)
        if root is not None:
            try:
                rel = pathlib.Path(path).relative_to(root)
            except ValueError:
                rel = None
            e = None
            # A multi-skill bundle's nested skills sit below its manifest
            # entry, so fall back to the nearest enclosing entry.
            while rel is not None and str(rel) not in (".", "") and e is None:
                e = idx.get(str(rel))
                rel = rel.parent
            if e:
                who = e.get("owner") or e.get("org") or e.get("provider")
                if not who and e.get("source"):
                    parts = str(e["source"]).split("://", 1)[-1].split("/")
                    if parts[0] in ("github.com", "gitlab.com") and len(parts) > 1:
                        parts = parts[1:]
                    who = parts[0]
                if who:
                    return f"{src}:{str(who).lower()}"
    return f"{src}:bundle:{d.get('_slug', '?')}"


def summarize(rows):
    stats = {
        "total_skills": len(rows),
        "by_source": {},
        "verdicts": Counter(),
        "severity_totals": Counter(),
        "rule_hits": Counter(),
        "rule_titles": {},
        "ast_hits": Counter(),
        "ast_titles": {},
        "risk_tiers": Counter(),
        "clean_skills": 0,
    }
    # rule -> bundles it fired in / publishers it fired in / findings per publisher
    rule_bundles = defaultdict(set)
    rule_pubs = defaultdict(Counter)
    publishers = set()
    per_source = defaultdict(lambda: {"n": 0, "pass": 0, "warn": 0, "fail": 0,
                                      "findings": 0, "risk_sum": 0,
                                      "sev": Counter()})
    skills = []
    for d in rows:
        src = d.get("_source", "?")
        verdict = d.get("verdict", "error")
        score = d.get("risk_score", 0) or 0
        tier = d.get("risk_tier", "?")
        counts = d.get("counts", {}) or {}
        findings = d.get("findings", []) or []
        stats["verdicts"][verdict] += 1
        pub = publisher_of(d)
        publishers.add(pub)
        stats["risk_tiers"][tier] += 1
        ps = per_source[src]
        ps["n"] += 1
        ps["risk_sum"] += score
        ps["findings"] += len(findings)
        # keep warn distinct from fail: a warn is not a failing verdict, and
        # folding it in overstates the per-source fail count.
        if verdict in ("pass", "warn"):
            ps[verdict] += 1
        else:
            ps["fail"] += 1
        if not findings:
            stats["clean_skills"] += 1
        for sev in SEV_ORDER:
            stats["severity_totals"][sev] += counts.get(sev, 0)
            ps["sev"][sev] += counts.get(sev, 0)
        for fdg in findings:
            rid = fdg.get("rule_id", "?")
            stats["rule_hits"][rid] += 1
            rule_bundles[rid].add((src, d.get("_slug", "?")))
            rule_pubs[rid][pub] += 1
            stats["rule_titles"][rid] = fdg.get("title", "")
            for a in (fdg.get("ast") or []):
                stats["ast_hits"][a] += 1
        for a, meta in (d.get("ast_references") or {}).items():
            stats["ast_titles"][a] = meta.get("title", "")
        top = [{"rule_id": f.get("rule_id"), "title": f.get("title"),
                "severity": f.get("severity"), "file": f.get("file"),
                "line": f.get("start_line"), "ast": f.get("ast") or [],
                "excerpt": (f.get("excerpt") or "").strip()[:90]}
               for f in findings]
        skills.append({
            "source": src, "slug": d.get("_slug", "?"),
            "verdict": verdict, "risk_score": score, "risk_tier": tier,
            "max_severity": d.get("max_severity", "info"),
            "counts": counts, "n_findings": len(findings),
            "findings": top,
        })
    for src, ps in per_source.items():
        stats["by_source"][src] = {
            "n": ps["n"], "pass": ps["pass"], "warn": ps["warn"],
            "fail": ps["fail"],
            "pass_rate": round(100 * ps["pass"] / ps["n"], 1) if ps["n"] else 0,
            "total_findings": ps["findings"],
            "avg_risk": round(ps["risk_sum"] / ps["n"], 1) if ps["n"] else 0,
            "severity": dict(ps["sev"]),
        }
    # Reach, de-duplicated by publisher: rule_hits counts findings, rule_bundles
    # bundles, rule_publishers distinct publishers. top_publisher_share is the
    # fraction of a rule's findings that came from its single largest publisher;
    # near 1.0 means the rule's count describes one author, not the population.
    stats["publishers_total"] = len(publishers)
    stats["rule_bundles"] = {r: len(b) for r, b in rule_bundles.items()}
    stats["rule_publishers"] = {r: len(c) for r, c in rule_pubs.items()}
    stats["rule_top_publisher_share"] = {
        r: round(c.most_common(1)[0][1] / sum(c.values()), 3)
        for r, c in rule_pubs.items()}
    stats["skills"] = sorted(skills, key=lambda s: (-s["risk_score"], s["source"], s["slug"]))
    # jsonify counters
    for k in ["verdicts", "severity_totals", "rule_hits", "ast_hits", "risk_tiers"]:
        stats[k] = dict(stats[k])
    return stats


def bar(n, total, width=24):
    if total == 0:
        return ""
    fill = int(round(width * n / total))
    return "█" * fill + "·" * (width - fill)


def md(stats):
    L = []
    A = L.append
    A(f"# {TITLE}\n")
    A(f"_Static scan of **{stats['total_skills']} real Agent Skills** "
      "against the surfaceguard ruleset (OWASP Agentic Skills Top 10)._\n")
    SRC_DESC = {
        "clawhub": "top skills by download count from the ClawHub registry (`clawhub.ai`)",
        "clawhub_more": "ClawHub skills ranked #41–140 by download count (`clawhub.ai`)",
        "anthropic": "the official `github.com/anthropics/skills` example skills",
        "skillsmp": "GitHub-indexed skills from SkillsMP (`sort=recent`, ≤5 per repo)",
        "orgs": "vendor repos via skills.rest — trailofbits, stripe, supabase, tinybird",
        "skillject": "`data/skills_sample` from the SkillJect malicious-skill research framework — real carrier skills, not pre-injected attacks",
    }
    A("| Corpus | Source |")
    A("|---|---|")
    for src in sorted(stats["by_source"]):
        A(f"| **{src}** | {SRC_DESC.get(src, 'skill bundles')} |")
    A("")

    # headline
    v = stats["verdicts"]
    npass = v.get("pass", 0)
    nfail = v.get("fail", 0)
    A("## Headline\n")
    A(f"- **{stats['total_skills']}** skills scanned "
      f"— **{npass} pass**, **{nfail} fail** "
      f"({round(100*nfail/stats['total_skills'],1)}% fail rate).")
    A(f"- **{stats['clean_skills']}** skills produced **zero findings**.")
    tot = stats["severity_totals"]
    A(f"- **{sum(tot.values())}** findings total — "
      f"crit {tot.get('critical',0)}, high {tot.get('high',0)}, "
      f"med {tot.get('medium',0)}, low {tot.get('low',0)}, info {tot.get('info',0)}.")
    A("")

    # by source
    A("## By corpus\n")
    A("| Corpus | Skills | Pass | Warn | Fail | Pass rate | Findings | Avg risk | crit | high | med | low |")
    A("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    for src in sorted(stats["by_source"]):
        s = stats["by_source"][src]
        sv = s["severity"]
        A(f"| {src} | {s['n']} | {s['pass']} | {s['warn']} | {s['fail']} | {s['pass_rate']}% | "
          f"{s['total_findings']} | {s['avg_risk']} | {sv.get('critical',0)} | "
          f"{sv.get('high',0)} | {sv.get('medium',0)} | {sv.get('low',0)} |")
    A("")

    # risk tiers
    A("## Risk tier distribution\n")
    A("| Tier | Skills | |")
    A("|---|--:|:--|")
    order = ["L0", "L1", "L2", "L3"]
    tiers = stats["risk_tiers"]
    tt = sum(tiers.values())
    for t in order + [x for x in tiers if x not in order]:
        if t in tiers:
            A(f"| {t} | {tiers[t]} | {bar(tiers[t], tt)} |")
    A("\n_L0 clean · L1 low · L2 elevated · L3 high-risk._\n")

    # top rules
    A("## Most-triggered rules\n")
    A(f"_Hits are findings. Bundles and publishers de-duplicate them: "
      f"{stats['total_skills']} bundles come from {stats['publishers_total']} "
      "publishers, and one author's sibling bundles can carry most of a rule's "
      "hits. Top-publisher share is the fraction of a rule's hits from its single "
      "largest publisher._\n")
    A("| Rule | Title | Hits | Bundles | Publishers | Top-publisher share |")
    A("|---|---|--:|--:|--:|--:|")
    for rid, n in sorted(stats["rule_hits"].items(), key=lambda x: -x[1])[:15]:
        A(f"| `{rid}` | {stats['rule_titles'].get(rid,'')} | {n} | "
          f"{stats['rule_bundles'].get(rid, 0)} | {stats['rule_publishers'].get(rid, 0)} | "
          f"{round(100 * stats['rule_top_publisher_share'].get(rid, 0))}% |")
    A("")

    # AST breakdown
    A("## OWASP Agentic Skills Top 10 coverage\n")
    A("| AST | Category | Findings |")
    A("|---|---|--:|")
    for a, n in sorted(stats["ast_hits"].items(), key=lambda x: -x[1]):
        A(f"| {a} | {stats['ast_titles'].get(a,'')} | {n} |")
    A("")

    # worst offenders
    A("## Highest-risk skills\n")
    A("| # | Corpus | Skill | Verdict | Risk | Tier | Max sev | Findings |")
    A("|--:|---|---|---|--:|---|---|--:|")
    ranked = [s for s in stats["skills"] if s["risk_score"] > 0][:15]
    for i, s in enumerate(ranked, 1):
        A(f"| {i} | {s['source']} | `{s['slug']}` | {s['verdict']} | "
          f"{s['risk_score']} | {s['risk_tier']} | {s['max_severity']} | {s['n_findings']} |")
    A("")

    # full table
    A("<details><summary>Full per-skill results (all "
      f"{stats['total_skills']})</summary>\n")
    A("| Corpus | Skill | Verdict | Risk | Tier | crit | high | med | low |")
    A("|---|---|---|--:|---|--:|--:|--:|--:|")
    for s in stats["skills"]:
        c = s["counts"]
        A(f"| {s['source']} | `{s['slug']}` | {s['verdict']} | {s['risk_score']} | "
          f"{s['risk_tier']} | {c.get('critical',0)} | {c.get('high',0)} | "
          f"{c.get('medium',0)} | {c.get('low',0)} |")
    A("\n</details>\n")

    A("## Notable cases (top findings per high-risk skill)\n")
    A("What actually tripped the scanner on the riskiest skills. These are "
      "**capability signals** mapped to OWASP AST, not proof of malice — surfaceguard "
      "is a static pre-load gate so a human or policy can decide.\n")
    for s in [x for x in stats["skills"] if x["risk_score"] > 0][:8]:
        A(f"**`{s['slug']}`** ({s['source']}) — risk {s['risk_score']} "
          f"({s['risk_tier']}), {s['n_findings']} findings")
        # de-dup findings by (rule, excerpt) and show up to 4
        seen, shown = set(), 0
        for f in s["findings"]:
            key = (f["rule_id"], f["excerpt"])
            if key in seen:
                continue
            seen.add(key)
            loc = f"{f['file']}:{f['line']}"
            ex = f["excerpt"].replace("\n", " ")
            A(f"  - `{f['rule_id']}` {f['severity']} — {f['title']} "
              f"— `{loc}` — `{ex}`")
            shown += 1
            if shown >= 4:
                break
        extra = s["n_findings"] - shown
        if extra > 0:
            A(f"  - …and {extra} more.")
        A("")
    A("## Methodology & caveats\n")
    corpus_bits = ", ".join(f"{stats['by_source'][s]['n']} {s}"
                            for s in sorted(stats["by_source"]))
    A(f"- **Corpus**: {corpus_bits}. ClawHub slugs are resolved to each slug's "
      "top publisher by download count; provenance in each corpus's `_manifest.json`.")
    A("- **Scan**: `surfaceguard scan <bundle> --format json`, the built-in "
      "rulepacks only (no custom policy/waivers), run in parallel.")
    A("- **Static only**: findings indicate *capability and pattern*, not confirmed "
      "intent or runtime behavior. A `pass` is not a safety guarantee; a `fail` is a "
      "prompt for review, waiver, or signing — not automatic condemnation.")
    A("- **Snapshot**: registry download counts and skill contents drift; results "
      "reflect the fetch date recorded in the manifests.")
    A("")

    A("---\n_Reproduce: `evaluation/scripts/fetch_clawhub.py`, "
      "`git clone anthropics/skills`, `evaluation/scripts/run_scans.sh`, "
      "`evaluation/scripts/aggregate.py`._")
    return "\n".join(L)


def main():
    rows = load()
    stats = summarize(rows)
    json.dump(stats, open(os.path.join(OUT, STATS_NAME), "w"), indent=2)
    open(os.path.join(OUT, REPORT_NAME), "w").write(md(stats))
    print(f"wrote {OUT}/{STATS_NAME} and {OUT}/{REPORT_NAME}")
    print(f"  {stats['total_skills']} skills, "
          f"{stats['verdicts'].get('pass',0)} pass / "
          f"{stats['verdicts'].get('fail',0)} fail")


if __name__ == "__main__":
    main()
