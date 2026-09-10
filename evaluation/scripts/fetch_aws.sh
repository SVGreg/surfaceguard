#!/usr/bin/env bash
# Fetch the AWS Agent Toolkit skills into evaluation/aws/.
#
# `aws/agent-toolkit-for-aws` is a single vendor repo carrying ~160 skill
# bundles — the largest first-party collection in the corpus, and one written to
# a house style: every skill ships `references/*.md`, links AWS documentation
# heavily, and describes cloud primitives (IMDS, IAM policies, sudo installs,
# credential paths) that the ruleset also treats as risk signals. That makes it
# the corpus's densest **false-positive proving ground**: it is curated, signed
# off by a vendor, and installed widely, so a finding here is a false positive
# until proven otherwise — the same regression-anchor role `orgs/` plays, at
# five times the size and with far more AWS-specific vocabulary.
#
# It is kept as its own corpus dir rather than folded into `orgs/` so its
# results can be read alone (`RAW_DIR=raw_aws`), the way `skillject/` is.
#
# This is a thin wrapper over fetch_orgs.sh, which already does the work:
# shallow-clone, find every SKILL.md, copy its directory, record provenance in
# _manifest.json. Nothing fetched is ever executed.
#
# Env: OUTDIR (default: aws), ORG_REPOS (default: aws/agent-toolkit-for-aws)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ORG_REPOS="${ORG_REPOS:-aws/agent-toolkit-for-aws}" \
OUTDIR="${OUTDIR:-aws}" \
  exec "$HERE/fetch_orgs.sh"
