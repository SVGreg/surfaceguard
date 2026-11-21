# surfaceguard — v1.0 Development Plan (execution tracker)

> **What this file is.** The executable breakdown of `docs/v1-dev-roadmap.md` into tasks that
> consecutive agent sessions can pick up, finish, and tick off. The roadmap says *what and why*;
> this file says *what is next, what it depends on, and how we know it is done*.
>
> **Who writes it:** `/sg-plan` (planning only — never code).
> **Who executes it:** `/sg-develop` (one task per cycle, one PR per cycle, merged once CI is green).
> **Only open work lives here.** When a milestone completes, collapse it to one line on the board;
> its cards, PR numbers and decisions are in git history, the code and the docs it shipped.

## How to read a task

Every task is one PR and one session's work. A task row is:

| Field | Meaning |
|---|---|
| **ID** | `M<milestone>-<nn>`, stable forever. Never renumber or reuse; a dropped task's id stays retired. |
| **Status** | `todo` · `in-progress` · `done` · `blocked` · `owner` · `dropped` |
| **Deps** | Task IDs that must be `done` first. Empty = startable now. |
| **PR** | Set by `sg-develop` when it opens the PR; the row flips to `done` when that PR merges. |

`blocked` = waiting on an external answer (record what, in the card).
`owner` = needs a human with credentials/accounts (marketplace publish, demo repo, key material).
`sg-develop` never picks `blocked` or `owner` rows; it reports them instead.

**Planning horizon.** Only the current and next milestone are expanded into full task cards.
Later milestones stay as task titles until `/sg-plan` expands them, re-checking the repo first.

**Numbering.** Milestones use the roadmap's M3–M8 (plus the owner-requested M9); the old ladder in
`docs/surfaceguard-design.md §14` is retired. Version labels are `release-please`'s call.

---

## 1. Milestone board

| Milestone | Theme | Status |
|---|---|---|
| **M3** | SARIF output + CI surface | done except M3-08 (owner) and M3-09 |
| **M4** | OMS + Sigstore keyless interop (keyless is the separate `keyless/` module) | **complete** |
| **M5** | Load-time / install-time gate (`guard`, verdict cache, hook) + skill cards | **complete** |
| **M6** | Taint analysis engine | **next — needs `/sg-plan`** |
| **M7** | LLM / semantic engine (opt-in) | needs `/sg-plan` |
| **M8** | Hardening (parallel) | needs `/sg-plan` |
| **M9** | Multi-skill discovery + installed-skill scan (`scan <path>...`, `--installed`, `locations`) | **complete** |
| **D** | Distribution track (parallel) | open rows below |

---

## 2. Cross-cutting definition of done

Applies to **every** task; `sg-develop` checks it before opening any PR. From roadmap §2.

- [ ] `gofmt -l .` empty · `go vet ./...` · `go test ./...` green
- [ ] Exit-code smoke: `scan testdata/malicious` → 1, `scan testdata/benign` → 0
- [ ] Backwards compatible: `scan`/`sign`/`verify` CLI surface and JSON shape are additive-only
- [ ] `ast_references` survives into every output format the task touches
- [ ] Any new network dependency ships its offline path **in the same task**
- [ ] Docs updated in the same PR (roadmap §2: docs ship with the feature)
- [ ] Rule-pack edits bump that pack's `version:` (CLAUDE.md / design §8.1)
- [ ] Perf budget intact: `scan` well under a second on a typical bundle; cached `verify` in
      single-digit ms

---

## M3 — open items

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| M3-08 | Public demo repo showing findings in the Security tab | owner | M3-06 | |
| M3-09 | Artifact URIs resolvable from the repo workspace (GitHub alert linking) | todo | M3-06 | |

### M3-09 — Repo-workspace-relative artifact URIs
**Why this exists.** Findings carry **bundle**-relative paths (`SKILL.md`, `scripts/setup.sh`), not
repo-relative ones, so a bundle scanned at `./skills/foo` yields `SKILL.md` — which GitHub resolves
against the checkout root and fails to link. M3-01 emits the SARIF-standard escape hatch
(`uriBaseId: SRCROOT` + `originalUriBaseIds`), but whether GitHub's uploader honours it must be
confirmed against a real upload, not assumed.
**Deliverables.** Confirm behavior with an actual code-scanning upload during M3-06; if the base id
is ignored, prefix result URIs with the scanned path (an emitter option, not a change to
`Finding.File`, which stays bundle-relative for the JSON contract).
**Acceptance.** An alert in the Security tab links to the correct file in the repo tree.

### M3-08 — Public demo (owner)
**Goal.** Close out M3 publicly.
**Blocked on the owner:** a public repo + Advanced Security enabled. Deliverable is a screenshot
or link in the M3 wrap-up showing findings with AST refs and a suppressed waiver.

---

## M6 — Taint analysis engine *(titles only)*

- M6-01 Source / sink / sanitizer model expressed in the YAML rule-pack style
- M6-02 Shell frontend · M6-03 Python frontend (cap the language set deliberately)
- M6-04 Instruction-flow analysis over `SKILL.md`
- M6-05 Lethal-Trifecta detector (sensitive data + untrusted content + egress in one flow)
- M6-06 Confidence integration + conservative defaults + `--strict`
- M6-07 Measured detection rate and FP rate on the evaluation corpora
- M6-08 Performance on large bundles

## M7 — LLM / semantic engine, opt-in *(titles only)*

- M7-01 Pluggable backend interface, off by default, no network in the default path
- M7-02 Semantic intent analysis of `SKILL.md` (obfuscated intent, social framing, smuggling)
- M7-03 LLM-derived findings tagged in text / JSON / SARIF; never suppress a deterministic finding
- M7-04 Optional triage mode (rank/explain existing findings)
- M7-05 Reproducibility record (model + version + prompt hash) and a disabled-path no-change test
- Note: `/sg-llm-polish` is a self-checking no-op until M7-01 lands; it becomes live here.

## M8 — Hardening *(titles only, runs in parallel)*

- M8-01 Skill SBOM + dependency provenance, drift detection vs signed state (AST07)
- M8-02 Cross-platform reuse safety — divergent runtime semantics (AST10)
- M8-03 Evasion corpus fixture + detections (padding, multi-layer encoding, zero-width, homoglyphs)
- M8-04 Over-privilege analysis: declared `allowed-tools` vs capabilities actually exercised (AST03)

## D — Distribution track (parallel from M3)

| ID | Task | Status | Deps | PR |
|---|---|---|---|---|
| D-01 | GitHub Action published to the marketplace | owner | M3-06 | |
| D-02 | Install paths: Homebrew tap, container image (GoReleaser already ships binaries) | todo | — | |
| D-03 | Marketplace / awesome-list registry listings | owner | — | |
| D-04 | Writeup: "Scanning and signing Agent Skills against OWASP AST10" | todo | M3-07 | |
| D-05 | Standards watch: AAIF / agentskills.io / OpenSSF signing work | todo | — | |
| D-06 | Reference integration in a real agent runtime or skill loader | todo | M5-05 | |

`D-05` is recurring, not one-shot: `/sg-plan` re-checks it whenever it expands a milestone, and
`/sg-threat-research` may feed it.

### D-01 — Publish the action to the marketplace *(owner)*
**Everything a repo can do for this is done** (see the marketplace-readiness pass): the action is
hardened, `LICENSE` exists (the README claimed Apache-2.0 with no file, which the listing shows),
`branding` is set, the release workflow maintains the floating **`v0`** tag the `uses:` line in the
README and in the M3-06 card always assumed, and the demo workflow installs published releases on
both runner OSes so a broken asset name fails CI rather than a user's build.

**What only the owner can do,** because it needs the repo's Settings and a release page:
1. Releases → the latest release → **Edit** → tick *Publish this Action to the GitHub Marketplace*,
   accept the terms, pick the categories (Security / Code quality). The listing name is
   **`Agent Skill Security Scan`** — spelled out rather than the brand, because marketplace search
   is keyword-driven. Marketplace names must be unique, and the brand alone is crowded there by
   unrelated projects, which is why the listing spells out what the action does.
2. Confirm the listing renders: icon (shield/blue), description, and the README's Action section.
3. After the next release, check `v0` moved (the `major-tag` job) — that is the ref the listing's
   copy-paste snippet hands people.

Nothing in the repo blocks step 1 any more; it is a five-minute UI task.

---

## Deferred — not scheduled in any milestone

Carried over from the first-drop handoff; `/sg-plan` folds an item into a milestone when it is picked up.

- Keyfile encryption at rest — the private `.key` is plaintext at mode 0600 today (age vs secretbox undecided).
- Rule-pack signing + trust enforcement for external `--rulepack` packs (design §8.2).
- git-URL / tar / zip bundle sources — `skill.LoadBundle` reads a directory or a single `SKILL.md`.
- C-ABI / Python / Node / Rust bindings and a daemon mode.
- OSV/CVE dependency lookup (`SG-DEP-003`) — needs an offline path before it can ship.
