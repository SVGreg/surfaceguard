#!/usr/bin/env python3
"""Find bundles the scanner scored clean that still contain risky primitives.

False positives are easy to audit — every rule hit is a candidate. *Misses* have
no such handle: a bundle that produces zero findings looks identical to a bundle
that is genuinely benign. This grep is the cheap counter-signal. It looks for a
small set of primitives that are almost always worth a human's attention, then
reports only the bundles where **surfaceguard found nothing at all**. Every line
it prints is a question ("should a rule have caught this?"), never a verdict.

It is deliberately independent of the rule packs: patterns here are written from
the attacker's idiom, not from what the packs already match, so overlap is
expected and hits that a pack *does* cover simply never reach the output.

Safety: this is the one place in the sweep where fetched bundle text is
summarised for a human. Nothing is executed, files are read as bytes, and every
excerpt is escaped (`unicode_escape`) and truncated, so terminal escapes,
bidi overrides and homoglyphs are rendered as literal `\\x..` sequences rather
than acted on by the terminal.

Usage:
    evaluation/scripts/sweep_gaps.py CORPUS_DIR [CORPUS_DIR ...]
    RAW_DIR=sweep-2026-09-07-skillssh evaluation/scripts/sweep_gaps.py ~/.cache/.../quarantine

Env:
    RAW_DIR   raw report dir under evaluation/reports/ (default: "raw"); used to
              decide which bundles the scanner already flagged. With no reports
              present, every bundle is treated as clean and everything is shown.
"""
import argparse
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RAW_DIR = os.environ.get("RAW_DIR", "raw")

MAX_FILE_BYTES = 512 * 1024
EXCERPT = 80

# (label, pattern). Kept short and idiom-shaped on purpose: this is a net for a
# human to read, not a detection rule.
PATTERNS = [
    ("pipe-to-shell",     rb"(?:curl|wget)[^\n]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b"),
    ("decode-to-shell",   rb"base64\s+(?:--decode|-d|-D)[^\n]{0,60}\|\s*(?:ba|z|)sh\b"),
    ("js-decode-eval",    rb"eval\s*\(\s*(?:atob|Buffer\.from)\s*\("),
    ("py-decode-exec",    rb"exec\s*\(\s*(?:base64|codecs|zlib|marshal)\."),
    ("cloud-credentials", rb"(?:\.aws/credentials|\.config/gcloud|\.azure/accessTokens)"),
    ("ssh-private-key",   rb"(?:\.ssh/id_(?:rsa|ed25519|ecdsa)\b|BEGIN\s+(?:RSA|OPENSSH)\s+PRIVATE\s+KEY)"),
    ("agent-config-write", rb"(?:\.claude/settings(?:\.local)?\.json|\.mcp\.json|claude_desktop_config\.json)"),
    ("env-harvest",       rb"(?:printenv|env\b[^\n]{0,20}\||os\.environ(?:\.items\(\)|\b\s*\))|process\.env\b)"
                          rb"[^\n]{0,120}(?:curl|fetch\(|requests\.(?:post|put)|http[s]?://)"),
    ("history-read",      rb"(?:\.bash_history|\.zsh_history|\.python_history)"),
    ("crontab-persist",   rb"(?:crontab\s+-|/etc/cron\.[a-z]+/|launchctl\s+load|systemctl\s+enable)"),
    ("webhook-egress",    rb"https?://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|"
                          rb"[a-z0-9-]+\.(?:ngrok|requestbin|webhook\.site|pipedream\.net))"),
]
COMPILED = [(name, re.compile(pat, re.I)) for name, pat in PATTERNS]

SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz",
            ".tar", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".wasm"}


def flagged_bundles():
    """Paths the scanner reported at least one finding for."""
    d = ROOT / "evaluation" / "reports" / RAW_DIR
    hit = set()
    if not d.is_dir():
        return hit
    for f in d.glob("*.json"):
        try:
            r = json.loads(f.read_text())
        except Exception:
            continue
        if r.get("findings") and r.get("_path"):
            hit.add(os.path.realpath(r["_path"]))
    return hit


def bundles(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "SKILL.md" in filenames:
            yield pathlib.Path(dirpath)


def escape(b):
    """Render an excerpt inert: escapes control bytes, ESC, bidi marks, homoglyphs."""
    s = b.decode("utf-8", "replace")[:EXCERPT].strip()
    return s.encode("unicode_escape").decode("ascii")


def scan_bundle(path):
    """[(label, relpath, lineno, escaped excerpt)] for one bundle."""
    out = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = pathlib.Path(dirpath) / name
            if p.suffix.lower() in SKIP_EXT or p.is_symlink() or not p.is_file():
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:4096]:          # binary
                continue
            for label, rx in COMPILED:
                for m in rx.finditer(data):
                    line = data.count(b"\n", 0, m.start()) + 1
                    start = data.rfind(b"\n", 0, m.start()) + 1
                    out.append((label, str(p.relative_to(path)), line,
                                escape(data[start:start + 200])))
                    break                        # one hit per pattern per file
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--all", action="store_true",
                    help="include bundles the scanner already flagged")
    a = ap.parse_args()

    flagged = set() if a.all else flagged_bundles()
    total = clean = shown = 0

    for root in a.roots:
        for b in sorted(bundles(pathlib.Path(root).expanduser())):
            total += 1
            if os.path.realpath(b) in flagged:
                continue
            clean += 1
            hits = scan_bundle(b)
            if not hits:
                continue
            shown += 1
            print(f"\n=== {b.name}")
            for label, rel, line, excerpt in hits:
                print(f"  [{label}] {rel}:{line}")
                print(f"      {excerpt}")

    print(f"\n[done] {total} bundles, {clean} with no findings, "
          f"{shown} of those carry a risky primitive — each is a possible miss to read.",
          file=sys.stderr)


if __name__ == "__main__":
    main()
