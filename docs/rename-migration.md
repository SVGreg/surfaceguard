# skill-guard → SurfaceGuard

The project was renamed in **v0.4.0**. This page says exactly what moved, what did
not, and what an existing user has to do (in most cases: nothing).

## Why

Two reasons, and the second is the one that matters long-term.

1. **The name was taken, twice, in this exact niche.** `vaibhavtupe/skill-guard`
   — an unrelated "quality gate for Agent Skills", whose repo predates this one by
   four months — already holds the `skill-guard` GitHub Marketplace listing, and
   `AI-Provenance/skillguard-core` holds `SkillGuard Scan`. A third tool with the
   same name helps nobody.
2. **The scope outgrew "skills".** What this tool actually guards is the set of
   artifacts a model is allowed to load: Agent Skills today, and plugins, MCP
   servers, tool definitions and rules files as they land. That set *is* the
   agent's attack surface, and the name now says so.

## What did **not** change

These are wire contracts. They appear in signatures, SARIF logs and skill cards
that already exist in the world, and renaming them would invalidate artifacts
nobody can regenerate. They keep the `SG`/`skillguard` spelling **by design** —
`SG` now reads as *SurfaceGuard*.

| Identifier | Example | Where it lives |
|---|---|---|
| Rule ids | `SG-INJ-001`, `SG-PRV-003` (89 ids) | every finding, SARIF result, policy waiver |
| Merkle format | `SGMT-1` | every attestation |
| Attestation file | `SKILL.md.skillsig` | signed bundles |
| DSSE payload type | `application/vnd.skillguard.attestation.v1+json` | every signature |
| Schema ids | `skillguard.net/skill-card/v1`, `…/rulepack.v1`, `…/policy.v1`, `…/attestation/v1` | cards, rule packs, policies |
| SARIF properties | `metadata.skillguard.risk_tier`, `skillguard_version` | emitted SARIF and card envelopes |

**A signature made by skill-guard v0.3.0 verifies under SurfaceGuard v0.4.0**, and
a policy written against the old rule ids still gates the same findings.

## What changed

| | Before | After |
|---|---|---|
| Binary | `skill-guard` | `surfaceguard` |
| Go module | `github.com/SVGreg/skill-guard` | `github.com/SVGreg/surfaceguard` |
| Repo | `SVGreg/skill-guard` | `SVGreg/surfaceguard` (GitHub redirects the old URL) |
| Policy file | `.skillguard.yaml` | `.surfaceguard.yaml` |
| Hook script | `hooks/skillguard_hook.py` | `hooks/surfaceguard_hook.py` |
| Hook config | `.claude/skillguard-hook.config.json` | `.claude/surfaceguard-hook.config.json` |
| Hook env var | `SKILLGUARD_HOOK_CONFIG` | `SURFACEGUARD_HOOK_CONFIG` |
| Hook config key | `skill_guard_bin` | `surfaceguard_bin` |
| Marketplace listing | *(unpublished)* | `Agent Skill Security Scan` |

## What you have to do

**Installing the binary** — nothing. `install.sh` is unchanged in usage, and
installing a **pre-rename version still works**: `VERSION=v0.3.0 sh install.sh`
detects that the release predates the rename, downloads its `skill-guard_*`
asset, checksums it, and installs it as `surfaceguard`.

**GitHub Action** — nothing. `uses: SVGreg/skill-guard@v0` keeps resolving through
GitHub's repo redirect; update it to `SVGreg/surfaceguard@v0` when convenient.

**The PreToolUse hook** — nothing immediately. The hook reads the pre-rename
config filename, env var and `skill_guard_bin` key, and falls back to a
`.skillguard.yaml` policy when no `.surfaceguard.yaml` exists — a rename must not
silently drop a working security configuration. Re-run `python3 hooks/install.py`
to point your settings at the renamed script.

**As a Go library** — update the import path to
`github.com/SVGreg/surfaceguard/...`. There is no redirect for module paths, and
the package layout is otherwise unchanged.

**Your `.skillguard.yaml`** — rename it at your leisure. The CLI takes the path
explicitly (`--policy`), so any filename works; only the hook's *default* moved,
and it falls back.

## What is deliberately not offered

There is no `skill-guard` shim binary. A security tool that answers to two names
is a tool whose logs, CI configs and audit trails disagree about what ran.
