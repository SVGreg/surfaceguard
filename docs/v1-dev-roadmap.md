# surfaceguard — Development Roadmap (v0.2 → v1.0)

> **Purpose of this document.** This is a machine-and-human readable roadmap intended to be
> handed to an agentic coding tool (Claude Code) as the source of truth for planning
> implementation work. It states *what* to build, *in what order*, *why that order*, and
> *how to know a milestone is done*. It deliberately does not prescribe internal code
> structure beyond existing package boundaries — the implementing agent should propose that.

**Repo:** `github.com/SVGreg/surfaceguard`
**Language:** Go (1.26+)
**Current state:** M3–M5 and M9 shipped — `scan` (single bundle, folders, `--installed`),
`guard`, `sign`/`verify` (SGMT-1 and OMS, keyless via `keyless/`), `locations`; outputs text /
JSON / SARIF / skill-card; a GitHub Action and a load-time hook. Next is M6.

---

## 0. Strategic framing (read this before planning)

surfaceguard competes in two sub-markets with very different dynamics:

| Sub-market | Competitive reality | Our stance |
|---|---|---|
| **Skill scanning / detection** | Crowded. Cisco AI Defense, Snyk `snyk-agent-scan`, Sentry, Mondoo, NVIDIA SkillSpector, Semgrep rules, academic tools. Several ship LLM + behavioral analysis. | Do **not** try to out-detect them. Compete on determinism, offline operation, AST10 fidelity, and CI ergonomics. |
| **Signing / provenance / verification** | Thin. Most rivals are scanners only. A de-facto standard exists (OpenSSF **OMS**, Sigstore-bundle based) but the only prominent implementation is vendor-anchored (NVIDIA, `nv-agent-root-cert.pem`). | **This is the wedge.** Become the vendor-neutral, Go-native, OSS implementation of skill signing + verification. |

**Three principles that constrain every decision below:**

1. **Determinism is the moat.** Static analysis, no code execution, no network required, single
   static binary. Anything that breaks "runs offline in CI and in air-gapped review" must be
   opt-in, never default.
2. **Interoperate, don't invent.** Where a standard exists (OMS, Sigstore, SARIF, AST10,
   skill cards), implement it. Bespoke formats isolate us.
3. **Distribution is currently the bottleneck, not capability.** Milestones that unlock
   adoption surfaces (SARIF → GitHub code scanning, GitHub Action, marketplace listings)
   outrank milestones that add depth.

### Explicit reprioritization decision

The previously stated intent was **LLM/semantic engine first**. This roadmap **reverses that**
and moves the LLM engine to last, as an optional plugin. Rationale:

- It attacks rivals at their strongest point (Cisco/Snyk/Mondoo/NVIDIA already ship semantic
  and behavioral analysis) with the fewest resources.
- It breaks the determinism moat: non-deterministic output, API keys, network dependency,
  hard-to-unit-test behavior.
- Cheaper, more defensible work is available first (SARIF is days; OMS interop is the
  strategic differentiator and leverages existing Sigstore/Cosign familiarity).

The LLM engine still gets built — as an **augmenting, opt-in backend** in M7, not as the core.

---

## 1. Milestone sequence (authoritative order)

```
M3  SARIF output + CI surface            ── unlock adoption        (days)
M4  OMS + Sigstore keyless interop       ── strategic wedge        (weeks)
M5  Load-time verification + skill cards ── differentiation        (1–2 weeks)
M6  Taint analysis engine                ── deterministic depth    (weeks)
M7  LLM/semantic engine (opt-in plugin)  ── augmentation           (weeks)
M8  Hardening: SBOM, AST07/AST10, evasion resistance               (ongoing)
```

Distribution work (§3) runs **in parallel** starting at M3, not after M8.

---

## M3–M5 — done

SARIF + GitHub Action (M3), OMS-compatible signing + Sigstore keyless verification (M4, keyless
signing in the separate `keyless/` module) and the load-time / install-time gate with skill cards
(M5) have shipped. The only open M3 items are tracked in `docs/v1-dev-plan.md`. The multi-skill
discovery milestone (M9) came from an owner request, not this roadmap, and is also complete.

---

## M6 — Taint analysis engine
**Priority:** medium-high. **Size:** medium → large. **Deterministic depth rivals' LLM passes lack.**

### Why
Pattern matching is explicitly called insufficient by the AST10 guidance. Taint analysis —
tracking data flow from untrusted sources to dangerous sinks — is the deterministic answer to
the "Lethal Trifecta" (sensitive-data access + untrusted content + external communication) and
raises precision without sacrificing offline determinism.

### Scope
- Source/sink/sanitizer model expressed in the existing data-driven YAML rule-pack style so
  the community can extend it without recompiling.
- Sources: skill inputs, fetched remote content, environment, files read.
- Sinks: network egress, shell/exec, file writes to sensitive paths, credential access.
- Analyze bundled scripts (start with shell + Python; design for pluggable language frontends)
  and instruction flows in `SKILL.md`.
- **Trifecta detector**: an explicit finding when all three legs co-occur in one flow.
- Confidence modifiers so taint findings integrate with existing scoring/threshold policy.

### Hard parts / risks
- Multi-language parsing scope creep — cap the initial language set deliberately.
- False-positive control; ship with conservative defaults and a `--strict` opt-in.
- Performance on large bundles.

### Done when
The trifecta detector fires on a curated corpus of known-malicious skill patterns with a
documented, measured false-positive rate on a known-good corpus.

---

## M7 — LLM / semantic analysis engine (opt-in plugin)
**Priority:** deliberately last. **Size:** medium.

### Why last
See §0. Building this first would be a me-too feature against better-resourced competitors and
would compromise the determinism moat. Built last, and correctly scoped, it becomes a genuine
augmentation instead of a liability.

### Non-negotiable constraints
- **Off by default.** Requires explicit flag/config plus a key. No network in the default path.
- **Never replaces** deterministic findings — it adds findings and may adjust confidence on
  existing ones, but a deterministic finding is never suppressed by an LLM verdict.
- **Pluggable backend interface** — support multiple providers (including Bedrock, given the
  target stack) behind one interface; no provider hard-coded.
- Deterministic reporting of non-determinism: record model + version + prompt hash in output
  so results are reproducible/auditable.
- Findings clearly tagged as LLM-derived in text/JSON/SARIF output.

### Scope
- Semantic intent analysis of `SKILL.md` instructions (obfuscated intent, social-engineering
  framing, instruction smuggling) where regex/AST cannot reach.
- Optional triage mode: rank/explain existing deterministic findings rather than generate new ones.

### Done when
Enabling the engine measurably improves detection on the evasion corpus from M8 without
changing any result when disabled.

---

## M8 — Hardening (parallel / ongoing)
**Size:** varies. These map to specific AST10 items that currently have no tooling.

- **Skill SBOM / dependency provenance (AST07 — Update Drift).** Emit an SBOM for a skill
  bundle; pin nested dependencies to immutable hashes; detect drift between a signed state
  and the current state.
- **Cross-platform reuse safety (AST10).** Detect constructs whose behavior differs across
  runtimes (Claude Code, Codex, Cursor, Gemini CLI, Goose) — differing tool permissions,
  frontmatter interpretation, `allowed-tools` semantics. No tooling exists here; this is a
  clean, ownable niche.
- **Evasion resistance.** Detect large-file padding (multi-MB README droppers), multi-layer
  encoding/obfuscation, zero-width and homoglyph tricks, and metadata that misrepresents
  bundle contents. Maintain an evasion corpus as a test fixture.
- **Over-privilege analysis (AST03).** Compare declared `allowed-tools` against capabilities
  actually exercised by the bundle; flag excess grants.

---

## 2. Cross-cutting engineering requirements

Apply to every milestone:

- **Backwards compatibility.** `scan`/`sign`/`verify` CLI surface and JSON output shape are
  contracts. Additive changes only until v1.0; breaking changes require a documented
  migration and a major-version bump.
- **Rule packs stay data-driven.** New detections should be expressible in YAML wherever
  possible, so contributors can add rules without Go changes.
- **AST10 traceability.** Every rule and finding keeps its `ast_references` mapping through
  every output format. This is a core differentiator — do not let it degrade.
- **Offline-first.** Any milestone that introduces a network dependency must ship an offline
  path in the same milestone.
- **Test corpora.** Maintain three fixture corpora: known-malicious, known-good, and evasion.
  Every detection milestone reports measured detection rate and false-positive rate against them.
- **Performance budget.** `scan` on a typical bundle stays well under a second; `verify`
  cached path stays in single-digit milliseconds.
- **Docs ship with the feature**, not after it.

---

## 3. Distribution track (runs in parallel from M3)

Capability is ahead of visibility. These are roadmap items, not afterthoughts:

1. **GitHub Action** published to the marketplace (built in M3; publishing is an owner step).
2. **Install paths**: Homebrew tap, `go install`, prebuilt binaries via existing GoReleaser
   setup, container image.
3. **Marketplace/registry listings** on skill marketplaces and awesome-lists in the
   MCP/Agent Skills ecosystem.
4. **A concrete writeup**: "Scanning and signing Agent Skills against OWASP AST10" — the
   AST10 mapping is a genuine differentiator and is currently undiscoverable.
5. **Standards engagement**: track AAIF / agentskills.io / OpenSSF work on skill signing and
   provenance. If an official standard ships, pivot immediately from bespoke format to best
   open implementation of that standard (M4 already positions for this).
6. **Reference integrations**: demonstrate the load-time gate inside at least one real
   agent runtime or skill loader.

---

## 4. Version targets

Release numbers are `release-please`'s call. **v1.0** = M8 items landed, output contracts frozen,
docs complete, and at least one external integration in the wild.

---

## 5. Explicit non-goals

- **Do not** build a SaaS dashboard or hosted registry. The value proposition is a local,
  deterministic, embeddable binary + library.
- **Do not** invent additional bespoke formats. Prefer OMS, Sigstore, SARIF, skill cards.
- **Do not** make the LLM engine a dependency of core scanning.
- **Do not** execute skill code as part of the default scan path. Any dynamic analysis, if it
  ever ships, is a separate opt-in mode with explicit sandboxing.
- **Do not** hard-code any vendor's root of trust.

---

## 6. Instructions for the implementing agent

When planning from this document:

1. Signing interop (OMS / Sigstore) is the strategic centerpiece; if effort must be cut, cut
   M6/M7 scope, never regress signing.
2. Re-check external specs and libraries against primary sources at implementation time —
   this roadmap's assumptions may be stale.
3. For each milestone, produce: a task breakdown, a proposed package layout, test-fixture
   requirements, and the acceptance criteria restated as executable checks.
4. Update README and docs as part of each milestone's work.
5. Where this roadmap and the repo disagree about current state, trust the repo and flag
   the discrepancy.
