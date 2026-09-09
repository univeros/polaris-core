# Decisions log

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.

## Open at start (decide in the WP indicated)

- **WP2** — `criteria` semantics for `RepositoryInterface::findBy/findOneBy`: equality, IN for lists, IS NULL for null. Confirm the domain uses nothing else; if it does, list it here.
- **WP2** — Default `EncrypterInterface`: libsodium XChaCha20-Poly1305 keyed from `Secrets`. Confirm key derivation is compatible with data encrypted by 1.0 (TOTP secrets), or provide a re-encryption path in `UPGRADE.md`.
- **WP3** — Identity map scope for `GenericRepository::persist` (per request vs per transaction).
- **WP4** — Reimplementation of the single `Cycle\Database\Injection\Fragment` usage per dialect.
- **WP5** — Meaning of the `suspended` validation rule (one occurrence) and whether it is validation or authorization.
- **WP5** — Whether `users/disable` stays `destructive` (see `effects.md`).
- **WP6** — Fixture normalisation rules (ids, timestamps, tokens, OTP codes) for the contract freeze.
- **WP1** — Which tests depend on Univeros wiring and are skipped until WP4/WP7 (keep the list here and empty it).
- **Any** — PHP minimum stays 8.3 (do not raise during extraction).

## Log

<!-- YYYY-MM-DD · WPn · decision · reason · rejected alternatives -->
- 2026-09-09 · WP0 · Root `composer.json` changes limited to `name` (`polaris/monorepo`), `description`, and `license` (MIT); `composer.lock` refreshed with `composer update --lock` (content-hash only, no dependency change). `keywords`, `homepage`, `support`, `type`, and the 1.0 autoload mapping stay until WP1 rewrites the root as the path-repository host. · Reason: WP0 is seed + rename; dependencies must not move before WP1. · Rejected: updating support URLs and keywords now (redone in WP1 anyway).
- 2026-09-09 · WP0 · No `LICENSE` file added; README "License" section (still "Proprietary") left untouched. · Reason: the copyright holder line is the owner's call, and README is the 1.0 Univeros-module README that gets rewritten when packages receive their own READMEs (WP1/WP8). `composer.json` is the licence source of truth meanwhile. · Rejected: guessing a copyright line; patching one README line in a document that is otherwise wrong for this repository.
- 2026-09-09 · WP0 · CI workflow kept as is: `composer validate --strict` plus the three separate `composer cs` / `composer stan` / `composer test` steps, rather than one `composer qa` step. · Reason: identical commands, clearer failure attribution in the Actions UI. · Rejected: collapsing into a single `composer qa` step (no gain).
- 2026-09-09 · WP0 · Each published package (`polaris/core`, `polaris/psr15`, `polaris/pdo`, `polaris/testing`, `polaris/cli`) gets its own read-only repository split from this monorepo, so a consumer requires one framework-agnostic package without pulling the monorepo or its siblings. This monorepo stays the single source of truth; nothing is committed to a split repository directly. · Reason: owner decision (2026-09-09); matches the "split-published" model in `coupling-analysis.md` and the per-package `v0.1.0` tags in `spec.md` §9. · Open for WP1: GitHub org and repository names, split tooling (subtree-split action vs. monorepo-builder), tag propagation. · Rejected: publishing from the monorepo root (Packagist needs one `composer.json` at each package repository's root).
- 2026-09-09 · WP1 · The seeded code keeps its `Univeros\Polaris\` namespace while moving to `packages/core/src`; each later WP renames the layers it ports to `Polaris\*`. · Reason: AGENT.md describes exactly this ("present until each layer is moved"); a wholesale rename is not in WP1's scope and would touch the 53 `api/*.yaml` class references that WP5 rewrites anyway. · Rejected: renaming everything in WP1.
- 2026-09-09 · WP1 · Each package manifest is truthful at every step: `packages/core/composer.json` requires the `univeros/*` packages its code still imports, and WP7 removes them when the last import goes. The root requires only the five `polaris/*` packages through one `packages/*` path repository, pinned to `0.1.x-dev` via the repository's `versions` option (path repositories otherwise guess the version from the current git branch); sibling packages require `polaris/core` as `^0.1`. · Rejected: parking the framework requirements in the root (core's manifest would lie about its own needs); Symfony-style `replace` at the root (duplicates every package's autoload mapping).
- 2026-09-09 · WP1 · `database/migrations` moves with core to `packages/core/database/` because `Module.php` resolves it relative to `src`; the whole directory is deleted in WP4 when `schema:export` replaces it. `api/` stays at the repository root per spec §1; nothing under `packages/` reads it until WP5.
- 2026-09-09 · WP1 · The forbidden-import check is `bin/check-imports`, a shell grep run by `composer imports` inside `composer qa` and by CI, reporting `Altair\`, `Cycle\`, the seeded `Univeros\Polaris\` namespace and any other `Univeros\` separately; advisory (exit 0) until WP5. · Reason: the spec allows a PHPStan rule or a grep; the grep also catches namespaces in strings and attributes, and needs no code. · Rejected: a custom PHPStan rule.
- 2026-09-09 · WP1 · Tests skipped because they need Univeros wiring: none. Nothing functional changed in WP1, so all 519 tests still run from `packages/core/tests`; the list is opened when WP2 or later has to skip something.
- 2026-09-09 · WP1 · `squizlabs/php_codesniffer` bumped to `^3.13.6` (dev-only) for CVE-2026-67434, the one advisory `composer audit` reported at WP0. No other dependency moves.
