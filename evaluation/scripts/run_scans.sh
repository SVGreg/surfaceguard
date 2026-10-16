#!/usr/bin/env bash
# Scan skill bundles in parallel and write one JSON report per skill.
#
# Usage: evaluation/scripts/run_scans.sh [PARALLELISM]
# Env:
#   CORPUS_DIRS  space-separated corpus dirs under CORPUS_ROOT (default: "clawhub anthropic")
#   CORPUS_ROOT  where those dirs live (default: evaluation/). Point it at a
#                quarantine directory outside the repo to scan a freshly fetched
#                sweep without the bundles ever touching the working tree.
#   RAW_DIR      output dir for raw JSON, relative to evaluation/reports/ (default: "raw")
#
# When every worker has finished, the script writes $RAW/.done holding the
# report count. Wait on that file, nothing else. The report count is not a
# signal: a worker's redirect creates its .json and .err the moment its scan
# starts, so the count is complete while the slowest bundles (minutes each)
# are still scanning. Nor is the process: `until ! pgrep -f run_scans.sh`
# matches the poller's own command line and never ends. A raw dir without
# .done is a run still going, or one that died.
set -uo pipefail

# The whole body is one { ...; exit; } group, so bash parses all of it before
# running any of it. Bash otherwise reads a script as it goes, and editing this
# file mid-run would change what the run executes next.
{

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/surfaceguard"
RAW="$ROOT/evaluation/reports/${RAW_DIR:-raw}"
JOBS="${1:-$(nproc 2>/dev/null || echo 4)}"
CORPUS_DIRS="${CORPUS_DIRS:-clawhub anthropic}"
CORPUS_ROOT="${CORPUS_ROOT:-$ROOT/evaluation}"

[ -x "$BIN" ] || { echo "building surfaceguard ..."; (cd "$ROOT" && go build -o surfaceguard ./cmd/surfaceguard) || exit 1; }

rm -rf "$RAW"; mkdir -p "$RAW"

# Discover skill bundle dirs: any directory directly containing a SKILL.md.
LIST="$(mktemp)"
CORPUS_PATHS=""
for c in $CORPUS_DIRS; do CORPUS_PATHS="$CORPUS_PATHS $CORPUS_ROOT/$c"; done
find $CORPUS_PATHS \
  -name SKILL.md -not -path '*/.git/*' -exec dirname {} \; | sort -u > "$LIST"

echo "found $(wc -l < "$LIST" | tr -d ' ') skill bundles; scanning with -P$JOBS ..."

scan_one() {
  local dir="$1" bin="$2" raw="$3" corpus_root="$4"
  local rel="${dir#"$corpus_root"/}"          # e.g. clawhub/github
  local source="${rel%%/*}"                    # clawhub | anthropic
  local slug="${rel#*/}"; slug="${slug//\//_}" # nested-safe
  local out="$raw/${source}__${slug}.json"
  "$bin" scan "$dir" --format json --no-color >"$out" 2>"$out.err"
  local code=$?
  # annotate with source/slug/exit for the aggregator
  python3 - "$out" "$source" "$slug" "$code" "$dir" <<'PY'
import json, sys
out, source, slug, code, path = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
try:
    d = json.load(open(out))
except Exception as e:
    d = {"_parse_error": str(e), "findings": [], "verdict": "error"}
d["_source"] = source
d["_slug"] = slug
d["_exit"] = code
d["_path"] = path
json.dump(d, open(out, "w"), indent=1)
PY
  printf '  %-9s %-34s exit=%s\n' "$source" "$slug" "$code"
}
export -f scan_one

tr '\n' '\0' < "$LIST" | xargs -0 -P"$JOBS" -I{} bash -c 'scan_one "$@"' _ {} "$BIN" "$RAW" "$CORPUS_ROOT"
rm -f "$LIST"

N="$(ls "$RAW"/*.json 2>/dev/null | wc -l | tr -d ' ')"
echo "$N" > "$RAW/.done"
echo "raw reports written to $RAW ($N files)"
exit
}
