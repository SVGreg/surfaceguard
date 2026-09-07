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

| Identifier | Example | Where it lives |
|---|---|---|
| Rule ids | `SG-INJ-001`, `SG-PRV-003` (89 ids) | every finding, SARIF result, policy waiver |
| Merkle format | `SGMT-1` | attestation prose and CLI help — it is a format *name*, not a field value |
| Attestation file | `SKILL.md.skillsig` | signed bundles |
| Key-id prefix | `sg-8f7164b591be` | trust rosters |
| OMS / Sigstore identifiers | `application/vnd.in-toto+json`, `https://in-toto.io/Statement/v1`, `https://model_signing/signature/v1.0` | `skill.oms.sig` — these belong to other specifications and are not ours to rename |

**A signature made by skill-guard v0.3.0 verifies under SurfaceGuard v0.4.0**, and
a policy written against the old rule ids still gates the same findings.

## Schema identifiers: renamed in 0.5.0

v0.4.0's table above also listed the schema ids and the DSSE payload type as
frozen. **That changed in 0.5.0**, deliberately and once: the project's
identifiers now live under a namespace it owns, which is what makes them
globally unique and what lets them resolve to a specification later.

| | Before | After | Shape it follows |
|---|---|---|---|
| Rule-pack `apiVersion` | `skillguard.net/rulepack.v1` | `surfaceguard.svgreg.net/rulepack.v1` | Kubernetes: bare `authority/name.vN`, never dereferenced |
| Policy `apiVersion` | `skillguard.net/policy.v1` | `surfaceguard.svgreg.net/policy.v1` | as above |
| Skill-card `_type` | `skillguard.net/skill-card/v1` | `https://surfaceguard.svgreg.net/skill-card/v1` | in-toto: a resolvable URI answering *what is this document* |
| Attestation `_type` | `skillguard.net/attestation/v1` | `https://surfaceguard.svgreg.net/attestation/v1` | as above |
| DSSE `payloadType` | `application/vnd.skillguard.attestation.v1+json` | `application/vnd.surfaceguard.attestation.v1+json` | DSSE/in-toto: a media type answering *how do I parse this* |
| USF `payloadType` | `application/vnd.skillguard.usf-fields.v1` | `application/vnd.surfaceguard.usf-fields.v1` | as above |
| Version field | `skillguard_version` | `surfaceguard_version` | attestation `scan` block, SARIF and card envelopes |

Two different conventions on purpose. `payloadType` and `_type` are **not**
interchangeable and must never converge: `pkg/verify` uses the payload type to
stop a USF field signature — published in plaintext in `SKILL.md` front-matter —
being replayed as a full attestation.

### What this costs you

**Signatures must be re-issued.** The DSSE payload type is inside the
pre-authentication encoding, so it is *signed material*: an attestation made
under the old spelling is not merely mislabelled, its signature is over
different bytes. Run `surfaceguard sign` again on anything you have signed.

Until v1, verification still **accepts** the old payload type and reports
`SG-PRV-008` (medium, "Legacy attestation payload type") instead of failing —
the signature is checked against the type the envelope itself declares, so it
verifies exactly as it was made. At v1 that acceptance is removed and the same
envelope reports `SG-PRV-002` (critical). Old **skill cards** stay readable with
no deprecation finding; only their identifier changed.

**Rule packs now declare a version, and it is checked.** `apiVersion` was parsed
and ignored before; it is now validated, and a pack that declares neither the
current id nor the pre-0.5 one is refused (`unsupported rule-pack apiVersion`).
This is the same fail-closed posture the engine registry already had. If you
maintain an external `--rulepack`, add:

```yaml
apiVersion: surfaceguard.svgreg.net/rulepack.v1
```

**Policies are not gated.** A `.surfaceguard.yaml` is *your* file: both ids are
read, and `apiVersion` remains optional.

**Nothing is ever fetched.** These identifiers are compared as strings. The
scanner performs no network I/O at all — the only networking in the project is
the separate `keyless/` module's Sigstore client.

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
