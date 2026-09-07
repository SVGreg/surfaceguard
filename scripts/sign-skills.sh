#!/usr/bin/env bash
#
# sign-skills.sh — sign every skill bundle in .claude/skills with both
# signature formats surfaceguard supports, each under its own key:
#
#   SKILL.md.skillsig  SGMT-1 Merkle root + DSSE attestation  <- --sgmt-key
#   skill.oms.sig      OpenSSF Model Signing v1.0 bundle      <- --oms-key
#
# `sign --oms` writes BOTH files from the single --key it is given, and there is
# no OMS-only mode, so two keys means two passes per bundle:
#
#   1. sign --key <oms-key> --oms   writes skill.oms.sig, plus a skillsig
#   2. sign --key <sgmt-key>        rewrites SKILL.md.skillsig under the SGMT key
#
# Pass 2 must come last: it replaces the throwaway attestation pass 1 left
# behind. The order is safe in the other direction too — pkg/skill's walk skips
# *.skillsig and skill.oms.sig, so neither signature file is an input to the
# other's digest, and rewriting one never invalidates the other.
#
# The OMS key must be ecdsa-p256: the OMS algorithm registry mandates EC
# P-256/384/521 and has no Ed25519 method. The SGMT key may be either.
#
# The binary is always rebuilt from the current sources into a temp dir, so a
# stale ./surfaceguard can never be what signed the skills.
#
# Usage: scripts/sign-skills.sh [options]
#   --skills-dir DIR   directory of skill bundles (default .claude/skills)
#   --sgmt-key PATH    key for SKILL.md.skillsig (default surfaceguard.key)
#   --oms-key PATH     ecdsa-p256 key for skill.oms.sig (default surfaceguard-oms.key)
#   --identity ID      publisher identity claim (default oidc:<git user.email>)
#   --ttl-days N       attestation validity in days (default: surfaceguard's 365)
#   --no-scan          integrity-only attestation (no scan result embedded)
#   --no-verify        skip the post-signing verify pass
#   -h, --help         this help

set -euo pipefail

SKILLS_DIR=".claude/skills"
SGMT_KEY="surfaceguard.key"
OMS_KEY="surfaceguard-oms.key"
IDENTITY=""
TTL_DAYS=""
NO_SCAN=0
VERIFY=1

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '/^# Usage:/,/^#   -h/p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
	case "$1" in
		--skills-dir) SKILLS_DIR="${2:?--skills-dir needs a value}"; shift 2 ;;
		--sgmt-key)   SGMT_KEY="${2:?--sgmt-key needs a value}"; shift 2 ;;
		--oms-key)    OMS_KEY="${2:?--oms-key needs a value}"; shift 2 ;;
		--identity)   IDENTITY="${2:?--identity needs a value}"; shift 2 ;;
		--ttl-days)   TTL_DAYS="${2:?--ttl-days needs a value}"; shift 2 ;;
		--no-scan)    NO_SCAN=1; shift ;;
		--no-verify)  VERIFY=0; shift ;;
		-h|--help)    usage; exit 0 ;;
		*)            die "unknown option: $1 (try --help)" ;;
	esac
done

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/.." && pwd))"
cd "$ROOT"

[ -d "$SKILLS_DIR" ] || die "no skills directory: $SKILLS_DIR"

# ---------------------------------------------------------------- key checks
key_field() { sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\(.*\\)\".*/\\1/p" "$1" | head -1; }

[ -f "$SGMT_KEY" ] || die "no SGMT-1 key at $SGMT_KEY
  create one with: surfaceguard keygen --out $SGMT_KEY"
[ -f "$OMS_KEY" ] || die "no OMS key at $OMS_KEY
  create one with: surfaceguard keygen --out $OMS_KEY --type ecdsa-p256"

# Fail before building rather than after: --oms refuses a non-EC key anyway,
# but a 2-second answer beats a 20-second one.
[ "$(key_field "$OMS_KEY" algorithm)" = "ecdsa-p256" ] ||
	die "$OMS_KEY is not an ecdsa-p256 key — OMS mandates EC P-256/384/521 and has no Ed25519 method.
  create an OMS-capable key with: surfaceguard keygen --out $OMS_KEY --type ecdsa-p256"

if [ -z "$IDENTITY" ]; then
	email="$(git config user.email 2>/dev/null || true)"
	[ -n "$email" ] && IDENTITY="oidc:$email"
fi

# Trust is local: a signature only "verifies" once the consumer has this key in
# their own trust.keys. Check the repo's own policy up front, because a signing
# run whose key is absent from the roster reports INVALID, not "untrusted" — and
# with two keys, BOTH have to be listed or one of the two formats fails.
POLICY="$ROOT/.surfaceguard.yaml"
UNTRUSTED_HINT=""
for k in "$SGMT_KEY" "$OMS_KEY"; do
	keyid="$(key_field "$k" keyid)"
	if [ -n "$keyid" ] && [ -f "$POLICY" ] && ! grep -q "$keyid" "$POLICY"; then
		UNTRUSTED_HINT="$UNTRUSTED_HINT
    - keyid: $keyid
      algorithm: $(key_field "$k" algorithm)
      public_key: $(key_field "$k" public_key)"
	fi
done
if [ -n "$UNTRUSTED_HINT" ]; then
	UNTRUSTED_HINT="  add to trust.keys in .surfaceguard.yaml (or the consumer's policy):$UNTRUSTED_HINT"
	printf 'note: a signing key is not in the trust roster of .surfaceguard.yaml\n%s\n\n' "$UNTRUSTED_HINT"
fi

# ------------------------------------------------------------------- build
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
BIN="$BUILD_DIR/surfaceguard"

printf 'building surfaceguard from current sources...\n'
go build -o "$BIN" ./cmd/surfaceguard || die "build failed"
printf '  %s\n' "$("$BIN" version | head -1)"
printf '  SGMT-1 key %s (%s)\n  OMS key    %s (%s)\n\n' \
	"$SGMT_KEY" "$(key_field "$SGMT_KEY" keyid)" "$OMS_KEY" "$(key_field "$OMS_KEY" keyid)"

# ------------------------------------------------------------------- sign
COMMON_ARGS=()
[ -n "$IDENTITY" ] && COMMON_ARGS+=(--identity "$IDENTITY")
[ -n "$TTL_DAYS" ] && COMMON_ARGS+=(--ttl-days "$TTL_DAYS")
[ "$NO_SCAN" -eq 1 ] && COMMON_ARGS+=(--no-scan)

signed=0
failed=0

# A skill bundle is any directory holding a SKILL.md.
while IFS= read -r manifest; do
	bundle="$(dirname "$manifest")"
	printf '==> %s\n' "$bundle"
	ok=1
	# Pass 1 (OMS key): writes skill.oms.sig, plus an attestation pass 2 discards.
	"$BIN" sign "$bundle" --key "$ROOT/$OMS_KEY" --oms "${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"}" >/dev/null || ok=0
	# Pass 2 (SGMT key): the attestation that ships. Overwrites pass 1's.
	"$BIN" sign "$bundle" --key "$ROOT/$SGMT_KEY" "${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"}" || ok=0
	[ "$ok" -eq 1 ] && printf '  wrote %s/skill.oms.sig\n' "$bundle"
	if [ "$ok" -eq 1 ]; then
		signed=$((signed + 1))
	else
		printf '    SIGN FAILED\n' >&2
		failed=$((failed + 1))
	fi
	printf '\n'
done < <(find "$SKILLS_DIR" -type f -name SKILL.md | sort)

[ $((signed + failed)) -gt 0 ] || die "no SKILL.md bundles found under $SKILLS_DIR"

# ------------------------------------------------------------------ verify
# Signing is only half the contract: verify re-reads both signatures against the
# repo policy's trust roster, so an untrusted signing key surfaces here and not
# on a consumer's machine.
verify_failed=0
if [ "$VERIFY" -eq 1 ]; then
	printf -- '--- verifying ---\n'
	VERIFY_ARGS=()
	[ -f "$POLICY" ] && VERIFY_ARGS+=(--policy "$POLICY")
	while IFS= read -r manifest; do
		bundle="$(dirname "$manifest")"
		if out="$("$BIN" verify "$bundle" "${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}" 2>&1)"; then
			printf '%-45s ok\n' "$bundle"
		else
			printf '%-45s VERIFY FAILED\n%s\n' "$bundle" "$out" >&2
			verify_failed=$((verify_failed + 1))
		fi
	done < <(find "$SKILLS_DIR" -type f -name SKILL.md | sort)
	printf '\n'
fi

# ----------------------------------------------------------------- summary
printf 'signed %d skill(s): SGMT-1 under %s, OMS under %s\n' \
	"$signed" "$(key_field "$SGMT_KEY" keyid)" "$(key_field "$OMS_KEY" keyid)"
[ "$failed" -gt 0 ] && printf '  %d failed to sign\n' "$failed" >&2
if [ "$verify_failed" -gt 0 ]; then
	printf '  %d failed to verify\n' "$verify_failed" >&2
	[ -n "$UNTRUSTED_HINT" ] && printf '  a signing key is missing from the trust roster, which is why a\n  signature reads INVALID rather than merely untrusted:\n%s\n' "$UNTRUSTED_HINT" >&2
fi

if [ "$failed" -gt 0 ] || [ "$verify_failed" -gt 0 ]; then
	exit 1
fi
