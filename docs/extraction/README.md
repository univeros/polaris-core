# Extraction of polaris/core — working folder

Everything needed to run task 1 (building the framework-agnostic `polaris/*` monorepo from a copy of `univeros/polaris` 1.0.0) lives here. The original `univeros/polaris` repository is not part of this work and is not modified.

| File | Read when |
|---|---|
| `spec.md` | Before starting any work package. The authoritative spec: ground rules, target layout, contracts to preserve, HTTP port, wiring, WP0–WP8 with acceptance criteria, definition of done. |
| `coupling-analysis.md` | When deciding what to touch in a directory. File-level map of what is framework-bound and how each layer is treated. |
| `target-design.md` | When a design question comes up that the spec does not answer (plugin contract, adapter conventions, security defaults). Its roadmap section is superseded by `spec.md`. |
| `effects.md` | During WP5. Pre-computed `effect`/`receipt` values for all 52 endpoint specs. |
| `decisions.md` | Whenever a choice is made that the spec left open. Append, never rewrite. |
| `behaviour-changes.md` | Whenever removing a dependency forces observable behaviour to change. Ideally stays empty. |

Working rules (from `spec.md` §0): no feature work; tests green at every merged step; public HTTP contract frozen; no `Altair\`, `Cycle\`, or `Univeros\` import survives past WP7, and none is ever added.

Branches: `extract/wp0` … `extract/wp8`, one at a time, each merged before the next starts.

## Status (2026-09-09)

Task 1 is done: WP0 to WP8 are merged. Against the definition of done (`spec.md` §9):

- Zero framework imports anywhere, CI-enforced (`bin/check-imports`); all suites green.
- Adapter conformance suite green on in-memory, SQLite and PostgreSQL (CI).
- The 52 routes are contract-frozen: 184 fixtures recorded from the 1.0 code replay through PSR-15, identical after normalisation, with one documented change (`behaviour-changes.md`).
- The Slim demo runs from a clean clone in about a minute (`examples/slim`).
- `behaviour-changes.md`, `effects.md` and `decisions.md` are in place; `univeros/polaris` is unchanged.
- `v0.1.0` (2026-09-10) is a GitHub release on the monorepo, one version line for the packages, the adapters and the client. The split to per-package repositories (`.github/workflows/split.yml`) runs once the owner sets the variables `SPLIT_ORG` and, where the names must not collide with the framework's own split, `SPLIT_PREFIX`, the secrets `SPLIT_TOKEN` and `PACKAGIST_AUTH` (the framework repository holds both), creates the eight empty repositories, and dispatches the workflow on the tag. Still open for the owner: a `LICENSE` file with the copyright line.
