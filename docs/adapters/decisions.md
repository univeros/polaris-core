# Decisions log (task 2, framework adapters)

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected. Task 1's log is `../extraction/decisions.md`.

## Open at start (decide in the WP indicated)

- **WP1** — The transport headers Laravel's kernel adds to every response (the harness allow-list, spec §0.2): at least `cache-control`; the first functional run decides the exact list.
- **WP1** — Whether the Laravel migration runs inside the migrator's transaction (`PdoAdapter::transaction()` opens its own) or opts out.
- **WP2** — The Symfony authenticator's role mapping (`ROLE_POLARIS_<ROLE>`) and whether the organization goes into a token attribute or the user.
- **WP2** — Doctrine DBAL connection reuse (`getNativeConnection()`) versus a separate PDO from the DSN when both are configured.
- **WP3** — `yiisoft/db` connection reuse (`getPDO()`) versus a DSN.
- **WP4** — The npm scope (`@polaris-auth/*` is the placeholder from `target-design.md` §9); the owner's call.
- **Any** — PHP minimum stays 8.3.

## Log

<!-- YYYY-MM-DD · WPn · decision · reason · rejected alternatives -->
- 2026-09-10 · WP0 · Task 2 is the three framework adapters plus the TypeScript client; the Agents and Cloud plugins are task 3 because they need the plugin contract (`target-design.md` §3.2), which is feature work on core with its own spec. · Reason: the extraction spec §10 lists both groups as "next tasks"; the adapters need no core feature, the plugins need one.
- 2026-09-10 · WP0 · Each adapter uses the framework's database connection through `polaris/pdo` (the PDO handle the framework already holds); no `polaris/eloquent` or `polaris/doctrine` adapter is built in this task. · Reason: `PdoAdapter` is what the conformance suite and the contract freeze run on; a second SQL path per framework would double the proof surface for no behaviour. · Rejected: dedicated ORM adapters (target-design §1 lists them; they wait for a need).
- 2026-09-10 · WP0 · The proof of an adapter is the unchanged functional suite plus the 184 fixtures through the framework's real HTTP kernel, selected by `POLARIS_HARNESS` (spec §3.7), with an explicit per-adapter allow-list of transport headers the framework adds to every response. · Reason: "no adapter changes a response" has to be checked by the same comparison that froze the contract; the allow-list keeps the framework's transport layer out of it without weakening the rest. · Rejected: a second, adapter-specific fixture set (would drift); stripping the framework's headers in the adapter (fighting the framework for the test's sake).
- 2026-09-10 · WP0 · Schema in a framework: the adapter's migration or command runs `SqlSchema` for the connection's dialect and seeds the catalog; no translation into Blueprint, Doctrine schema or Yii migrations. · Reason: one source of DDL, proven by `schema:diff`; a translation would be a second schema to keep equal. · Rejected: `schema:export --target=laravel|doctrine` emitting builder code (task 1 left the targets to the adapters; this decides what they are).
