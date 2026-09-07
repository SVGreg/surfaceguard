#!/usr/bin/env python3
"""Remember which skills a sweep already saw, so the next one goes somewhere new.

A registry's install ranking barely moves between sweeps, so an uncapped
"fetch the top 150" fetches almost the same 150 every cycle: the same bundles
re-scanned, the long tail never seen. This ledger fixes that, and the fix has a
second, more valuable half — a bundle we have already scanned is worth
*re-*scanning exactly when something changed, and "something" is one of three
things:

  1. our detections moved   — the rule packs are at different versions
  2. the skill moved        — its source repo has new commits
  3. enough time passed     — the TTL backstop

Rule 1 is the one that actually fires. A wall-clock TTL asks "is this stale?"
when the question we care about is "would we score it differently now?", and
that changes when a pack version changes, not when a calendar page turns.

Rule 2 makes drift visible: a popular skill whose bytes changed since we last
looked is the single most security-relevant thing a repeated sweep can produce,
and it is this project's own thesis — a scan claim binds to a content hash, not
to a name. The `git ls-remote` check is coarse (it sees any commit to the repo,
not to the bundle) so it over-fetches rather than under-fetches; the precise
answer is the `content_hash` comparison this script records after the fetch.

Ledger lives at `.claude/maintenance/corpus-seen.json` — per-machine loop state,
git-ignored, the same class of thing as `state.json`. Losing it costs one
redundant sweep, nothing more.

Usage:
    corpus_ledger.py record --source skillssh --raw-dir sweep-2026-09-07-skillssh
    corpus_ledger.py stats
    corpus_ledger.py prune

`fetch_skillssh.py` imports `decide()` and `pack_versions()` from here when
LEDGER_SOURCE is set; nothing consults the ledger unless a sweep asks it to, so
building a pinned corpus stays deterministic.

Env:
    CORPUS_LEDGER  path to the ledger (default .claude/maintenance/corpus-seen.json)
    LEDGER_TTL_DAYS  revisit backstop in days (default 60)
"""
import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = pathlib.Path(os.environ.get("CORPUS_LEDGER")
                      or ROOT / ".claude" / "maintenance" / "corpus-seen.json")
TTL_DAYS = int(os.environ.get("LEDGER_TTL_DAYS", "60"))
VERSION = 1

# Sources whose bundles are always re-fetched. `orgs` is the regression anchor:
# its whole job is being re-scanned every cycle, so it must never be skipped.
NEVER_SKIP = {"orgs"}


def today():
    return datetime.date.today().isoformat()


def load():
    try:
        d = json.loads(LEDGER.read_text())
        if d.get("version") == VERSION and isinstance(d.get("skills"), dict):
            return d
    except (OSError, ValueError):
        pass
    return {"version": VERSION, "skills": {}}


def save(d):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps(d, indent=1, sort_keys=True) + "\n")


def pack_versions(binary=None):
    """{pack: semver} as reported by the scanner that will do the scanning."""
    binary = binary or str(ROOT / "surfaceguard")
    out = {}
    try:
        r = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return out
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("rulepack ") and "@" in line:
            name, _, rest = line[len("rulepack "):].partition("@")
            out[name] = rest.split()[0]
    return out


def content_hash(bundle_dir, binary=None):
    """The bundle's canonical content hash, via `guard --no-scan` (~2 ms)."""
    binary = binary or str(ROOT / "surfaceguard")
    try:
        r = subprocess.run([binary, "guard", str(bundle_dir), "--no-scan",
                            "--format", "json", "--no-color"],
                           capture_output=True, text=True, timeout=60)
        return (json.loads(r.stdout) or {}).get("content_hash")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def days_since(iso):
    try:
        d = datetime.date.fromisoformat(iso)
    except (TypeError, ValueError):
        return 10**6
    return (datetime.date.today() - d).days


def decide(key, entry, packs, repo_head=None, ttl_days=TTL_DAYS, source=None):
    """(fetch?, reason) for one candidate. Cheap checks first — repo_head last.

    Pass repo_head=None to defer the network check: a caller that wants to avoid
    an `ls-remote` for a bundle already condemned by a cheaper rule can call
    twice, once without it and once with.
    """
    if source in NEVER_SKIP:
        return True, "regression anchor (never skipped)"
    if not entry:
        return True, "not seen before"
    age = days_since(entry.get("last_fetched"))
    if age >= ttl_days:
        return True, f"TTL: last seen {age}d ago"
    if packs and entry.get("packs") and entry["packs"] != packs:
        moved = sorted(p for p in set(packs) | set(entry["packs"])
                       if packs.get(p) != entry["packs"].get(p))
        return True, "packs moved: " + ", ".join(moved[:3])
    if repo_head is None:
        return False, "deferred"          # caller still owes the ls-remote check
    if entry.get("repo_commit") and repo_head != entry["repo_commit"]:
        return True, "source repo has new commits"
    return False, f"unchanged, seen {age}d ago"


def repo_head(repo, timeout=25):
    """Current HEAD sha of a GitHub repo — one round trip, no clone."""
    try:
        r = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}", "HEAD"],
                           capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
        line = r.stdout.strip().split("\n")[0]
        return line.split()[0] if line else None
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


# ─── record: fold one sweep's scan results back into the ledger ───

def cmd_record(a):
    raw = ROOT / "evaluation" / "reports" / a.raw_dir
    if not raw.is_dir():
        sys.exit(f"no such raw report dir: {raw}")

    manifest = {}
    if a.manifest and pathlib.Path(a.manifest).is_file():
        for e in json.loads(pathlib.Path(a.manifest).read_text()):
            manifest[e.get("slug")] = e

    led = load()
    packs = pack_versions(a.binary)
    drifted, changed_verdict, new = [], [], 0

    for f in sorted(raw.glob("*.json")):
        try:
            rep = json.loads(f.read_text())
        except ValueError:
            continue
        slug, path = rep.get("_slug"), rep.get("_path")
        if not slug or not path:
            continue
        key = f"{a.source}/{slug}"
        prior = led["skills"].get(key)
        h = content_hash(path, a.binary)
        verdict = rep.get("verdict")
        n = len(rep.get("findings") or [])

        if prior is None:
            new += 1
        else:
            if h and prior.get("content_hash") and h != prior["content_hash"]:
                drifted.append((key, prior.get("last_fetched"), prior.get("verdict"), verdict))
                if verdict != prior.get("verdict"):
                    changed_verdict.append(key)

        m = manifest.get(slug, {})
        led["skills"][key] = {
            "source": a.source,
            "repo": m.get("source") or (prior or {}).get("repo"),
            "repo_commit": m.get("commit") or (prior or {}).get("repo_commit"),
            "content_hash": h or (prior or {}).get("content_hash"),
            "last_fetched": today(),
            "packs": packs or (prior or {}).get("packs") or {},
            "verdict": verdict,
            "findings": n,
        }

    save(led)
    total = sum(1 for k in led["skills"] if k.startswith(a.source + "/"))
    print(f"[ledger] {a.source}: {new} new, {len(drifted)} drifted, "
          f"{total} known; {len(led['skills'])} entries total -> {LEDGER}")
    if drifted:
        print("\nD — drift (content changed since the ledger last saw it):")
        for key, seen, old_v, new_v in drifted:
            mark = "  <- VERDICT CHANGED" if old_v != new_v else ""
            print(f"  {key}\n      last seen {seen}: {old_v} -> {new_v}{mark}")
    if changed_verdict:
        print(f"\n{len(changed_verdict)} of those now scan differently — read these first.")


def cmd_stats(a):
    led = load()
    by_source, ages = {}, []
    for k, e in led["skills"].items():
        by_source[e.get("source", "?")] = by_source.get(e.get("source", "?"), 0) + 1
        ages.append(days_since(e.get("last_fetched")))
    print(f"{LEDGER} — {len(led['skills'])} entries")
    for s, n in sorted(by_source.items(), key=lambda kv: -kv[1]):
        print(f"  {s:<12} {n:>5}")
    if ages:
        ages.sort()
        print(f"  age (days): min {ages[0]}, median {ages[len(ages) // 2]}, max {ages[-1]}")
        due = sum(1 for x in ages if x >= TTL_DAYS)
        print(f"  {due} past the {TTL_DAYS}d TTL and due for a revisit")


def cmd_prune(a):
    """Drop entries so old that a revisit is guaranteed anyway."""
    led = load()
    cutoff = a.older_than or TTL_DAYS * 2
    before = len(led["skills"])
    led["skills"] = {k: e for k, e in led["skills"].items()
                     if days_since(e.get("last_fetched")) < cutoff}
    save(led)
    print(f"[ledger] pruned {before - len(led['skills'])} entries older than {cutoff}d; "
          f"{len(led['skills'])} remain")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record", help="fold a sweep's scan results into the ledger")
    r.add_argument("--source", required=True)
    r.add_argument("--raw-dir", required=True, help="dir under evaluation/reports/")
    r.add_argument("--manifest", help="the sweep's _manifest.json, for repo/commit")
    r.add_argument("--binary", help="surfaceguard binary (default ./surfaceguard)")
    r.set_defaults(func=cmd_record)

    s = sub.add_parser("stats", help="what the ledger knows")
    s.set_defaults(func=cmd_stats)

    p = sub.add_parser("prune", help="drop entries a revisit would refetch anyway")
    p.add_argument("--older-than", type=int)
    p.set_defaults(func=cmd_prune)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
