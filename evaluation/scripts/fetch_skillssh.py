#!/usr/bin/env python3
"""Fetch the most-installed skills.sh skills into <OUTROOT>/<OUTDIR>/<slug>.

skills.sh indexes tens of thousands of Agent Skills and reports an *install*
count per skill, which is a different popularity signal from ClawHub's download
count and from GitHub stars — so this corpus is a third independent slice, not a
re-cut of `clawhub/`.

Pipeline:
  1. GET /api/search?q=<term>&limit=100 for each seed term -> ranked candidates
     (there is no list-all endpoint; a seed sweep is how you approximate one)
  2. dedup by id, sort by installs desc, keep WANT
  3. shallow-clone each distinct source repo once, copy out the skill directory

Safety (this fetches third-party content that may be hostile):
  - nothing is ever executed: clone runs with hooks disabled, no submodules,
    no checkout of anything but the default branch tip; no install step
  - symlinks and non-regular files are never copied
  - per-file, per-bundle and file-count caps bound what lands on disk
  - only directories that actually contain a SKILL.md are kept

Env:
  WANT        how many skills to keep          (default 200)
  OUTROOT     root the corpus dir lives under  (default evaluation/)
  OUTDIR      corpus dir name under OUTROOT    (default skillssh)
  SKIP_DIRS   comma-separated corpus dirs whose slugs are already loaded
  SEEDS       comma-separated search terms overriding the default sweep
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

API = "https://skills.sh/api/search"
UA = "surfaceguard-eval/0.1"

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.environ.get("OUTROOT") or os.path.join(HERE, "..")
OUT_NAME = os.environ.get("OUTDIR", "skillssh")
OUT_DIR = os.path.join(OUT_ROOT, OUT_NAME)
WANT = int(os.environ.get("WANT", "200"))
SKIP_DIRS = [d for d in os.environ.get("SKIP_DIRS", "").split(",") if d]

# The search API needs a query of >= 2 characters and has no "list everything"
# mode, so popularity is approximated by sweeping broad terms and ranking the
# union. Terms are deliberately generic — they are a net, not a topic filter.
SEEDS = [s for s in os.environ.get("SEEDS", "").split(",") if s] or [
    "code", "test", "review", "web", "api", "data", "docs", "git",
    "python", "typescript", "react", "database", "cloud", "deploy",
    "security", "debug", "design", "agent", "build", "search",
    "write", "analysis", "workflow", "mcp", "shell", "ui",
]

# Caps on what a single bundle may drop on disk.
MAX_FILE_BYTES = 1 << 20        # 1 MiB per file
MAX_BUNDLE_BYTES = 10 << 20     # 10 MiB per bundle
MAX_BUNDLE_FILES = 1000


def search(term, limit=100):
    """Return the raw skill records the API reports for one term."""
    params = urllib.parse.urlencode({"q": term, "limit": str(limit)})
    req = urllib.request.Request(f"{API}?{params}",
                                 headers={"Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=25) as r:
        return (json.loads(r.read()) or {}).get("skills", []) or []


def ranked(want):
    """[(id, source_repo, skill_id, installs)] over the seed sweep, best first."""
    seen = {}
    for term in SEEDS:
        try:
            hits = search(term)
        except Exception as e:                       # one dead term must not stop the sweep
            print(f"    ! search({term!r}) failed: {e}", file=sys.stderr)
            continue
        for h in hits:
            sid, src = h.get("id"), h.get("source")
            if not sid or not src or src.count("/") != 1:
                continue                             # only owner/repo sources are fetchable
            seen[sid] = (sid, src, h.get("skillId") or sid.rsplit("/", 1)[-1],
                         h.get("installs") or 0)
        time.sleep(0.15)
    return sorted(seen.values(), key=lambda r: -r[3])[:want]


def load_skip():
    """Slugs already present in other corpus dirs (SKIP_DIRS)."""
    skip = set()
    for d in SKIP_DIRS:
        base = os.path.join(HERE, "..", d)
        if os.path.isdir(base):
            for name in os.listdir(base):
                if os.path.exists(os.path.join(base, name, "SKILL.md")):
                    skip.add(name)
    return skip


def clone(repo, dest):
    """Shallow-clone a repo with hooks disabled and nothing executed."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", GCM_INTERACTIVE="never")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "clone", "--depth", "1", "--single-branch", "--no-tags",
           "--recurse-submodules=no", "--quiet",
           f"https://github.com/{repo}", dest]
    return subprocess.run(cmd, env=env, timeout=180,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def head_sha(repo_dir):
    try:
        out = subprocess.run(["git", "-C", repo_dir, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def find_bundle(repo_dir, skill_id):
    """Directory of the SKILL.md whose folder is named skill_id, else the first one."""
    hits = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        if "SKILL.md" in files:
            hits.append(root)
    if not hits:
        return None
    for h in hits:
        if os.path.basename(h) == skill_id:
            return h
    return hits[0]


def copy_bundle(src, dest):
    """Copy a bundle, refusing symlinks and anything over the caps."""
    total = files = 0
    staged = []
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if d != ".git" and not os.path.islink(os.path.join(root, d))]
        for n in names:
            p = os.path.join(root, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue                             # never follow a link out of the bundle
            size = os.path.getsize(p)
            if size > MAX_FILE_BYTES:
                continue
            files += 1
            total += size
            if files > MAX_BUNDLE_FILES or total > MAX_BUNDLE_BYTES:
                return False
            staged.append((p, os.path.relpath(p, src)))
    if not any(rel == "SKILL.md" for _, rel in staged):
        return False
    shutil.rmtree(dest, ignore_errors=True)
    for p, rel in staged:
        target = os.path.normpath(os.path.join(dest, rel))
        if not target.startswith(os.path.normpath(dest) + os.sep):
            continue                                 # path-traversal guard, as in fetch_clawhub
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(p, target)
    return True


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    skip = load_skip()
    pool = WANT + len(skip) + 40
    print(f"[*] sweeping {len(SEEDS)} seed terms; want {WANT} skills by installs "
          f"(skipping {len(skip)} already loaded) -> {OUT_DIR}", flush=True)
    candidates = ranked(pool)
    print(f"[*] {len(candidates)} distinct candidates ranked", flush=True)

    # Group by repo so a repo publishing 30 skills is cloned once, not 30 times.
    by_repo = {}
    for sid, src, skill_id, installs in candidates:
        by_repo.setdefault(src, []).append((sid, skill_id, installs))

    manifest, ok = [], 0
    tmp = tempfile.mkdtemp(prefix="sg-skillssh-")
    try:
        for repo, entries in by_repo.items():
            if ok >= WANT:
                break
            repo_dir = os.path.join(tmp, repo.replace("/", "__"))
            if not clone(repo, repo_dir):
                print(f"    - {repo:<40} SKIP (clone failed)")
                continue
            sha = head_sha(repo_dir)
            for sid, skill_id, installs in entries:
                if ok >= WANT:
                    break
                slug = sid.replace("/", "__")
                slug = "".join(c if (c.isalnum() or c in "_.-") else "_" for c in slug)
                if slug in skip:
                    continue
                bundle = find_bundle(repo_dir, skill_id)
                if not bundle:
                    print(f"    - {sid:<50} SKIP (no SKILL.md)")
                    continue
                dest = os.path.join(OUT_DIR, slug)
                if not copy_bundle(bundle, dest):
                    print(f"    - {sid:<50} SKIP (over caps / no SKILL.md)")
                    continue
                ok += 1
                manifest.append({
                    "slug": slug,
                    "dir": f"{OUT_NAME}/{slug}",
                    "source": repo,
                    "skill_id": skill_id,
                    "skill_path": os.path.relpath(bundle, repo_dir),
                    "commit": sha,
                    "installs": installs,
                    "registry": "skills.sh",
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
                print(f"[{ok:>3}] {sid:<50} OK  ({installs:,} installs)")
            shutil.rmtree(repo_dir, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    with open(os.path.join(OUT_DIR, "_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[done] {ok} bundles saved -> {OUT_DIR}")


if __name__ == "__main__":
    main()
