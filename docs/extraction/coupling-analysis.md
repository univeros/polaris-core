# Polaris extraction plan — from `univeros/polaris` 1.0.0 to `polaris/core`

Based on the public repo at tag v1.0.0 (commit 17ec933, 2026-06-11): 252 source files, ~16.2k LOC, 115 test files, 52 YAML endpoint specs, 18 migrations.

**Goal.** A framework-free `polaris/core` that a PSR-15 handler and later Laravel/Symfony/Yii adapters consume — with the 115 tests carried over and green at every step.

**Approach.** A new repository `polaris` (`~/projects/polaris-core`), seeded from `univeros/polaris` v1.0.0 with history, restructured as a `packages/` monorepo and split-published. `univeros/polaris` is left untouched and keeps serving Univeros hosts. The treatments below describe what happens to each directory in the copy.

---

## 1. Coupling map (what is actually attached to the framework)

| Directory | Files | Coupled | What the coupling is | Treatment |
|---|---:|---:|---|---|
| `Contracts` | 7 | 0 | — | **Keep** → `core/Contract` |
| `Event` | 35 | 0 | — | **Keep** → `core/Event` |
| `Exception` | 25 | 0 | — | **Keep** → `core/Exception` |
| `Security` | 4 | 0 | — | **Keep** |
| `Support` | 1 | 0 | — | **Keep** |
| `Config` | 7 | 1 | one framework config type | **Keep**, replace one import |
| `Identity` | 14 | 7 | `RepositoryInterface`, `UnitOfWorkInterface`, `CycleIdentityProvider` | **Relocate interfaces**; `CycleIdentityProvider` moves to the Univeros adapter |
| `Mfa` | 21 | 8 | `RepositoryInterface`, `UnitOfWorkInterface`, `EncrypterInterface` | **Relocate interfaces** |
| `Token` | 15 | 7 | `Token*Interface` family, `LcobucciTokenParser` | **Relocate interfaces**; own the JWT contracts |
| `Authorization` | 12 | 9 | `RepositoryInterface`, middleware/guard types from `Altair\Http` | **Relocate interfaces**; guard becomes a core service, middleware moves to adapters |
| `Entity` | 15 | 15 | Cycle annotations | **Strip annotations** → plain records; schema declared separately |
| `Persistence` | 15 | 15 | `CycleRepository`, `ORMInterface` | **Rewrite once** over a `DatabaseAdapter`; Cycle becomes one adapter |
| `Http/Auth`, `Http/Orgs`, `Http/Users`, `Http/Rule`, `Http/Jwks` | 56 | 56 | `InputCollection`, `PayloadInterface`, `AuthDomain` base | **Mechanical port**: the classes are thin (parse → call service → map exception → body); swap two types |
| `Http/Middleware` | 13 | 11 | PSR-15 already, plus `Altair\Http` helpers | **Keep as PSR-15** in `psr15` package; Univeros adapter re-exports with priorities |
| `Bootstrap` | 7 | 6 | `Altair\Container` bindings | **Replace** with a container-free `Polaris::create()` wiring; Univeros adapter keeps container bindings |
| `Observability`, `Maintenance`, `Notification` | 4 | 4 | framework observability + scheduler hooks | **Port to PSR-3/PSR-14**; scheduler hook moves to adapters |
| `Module.php` | 1 | 1 | Univeros module contracts | **Moves whole** to `packages/univeros` |

Net: ~72 files untouched, ~60 need only import changes, ~85 are rewritten mechanically against new types, ~30 (Entity + Persistence) are re-based on a database adapter.

---

## 2. Interfaces to own (the "relocation" step)

Copy these into `Polaris\Contract\*` with identical signatures, then repoint imports. The Univeros adapter bridges them to `Altair\*` in a few lines each.

From `Altair\Persistence\Contracts`:
- `RepositoryInterface<T>` — used 24× in the domain
- `UnitOfWorkInterface` — used 16×

From `Altair\Http\Contracts`:
- `TokenInterface`, `TokenGeneratorInterface`, `TokenParserInterface`, `TokenValidatorInterface`, `TokenFactoryInterface`, `TokenConfigurationInterface`, `IdentityProviderInterface`

From `Altair\Http\Exception`:
- `InvalidTokenException`, `AuthorizationTokenException` → become `Polaris\Exception\*`

From `Altair\Security\Contracts`:
- `EncrypterInterface` (+ `DecryptException`)

After this step alone, `Identity`, `Mfa`, `Token`, `Authorization`, `Security`, `Config`, `Event`, `Exception`, `Contracts` — about 140 files — compile with no `Altair\` import. Run the unit tests for those layers here; nothing else has changed.

---

## 3. Persistence: from Cycle entities to schema-as-data

**Entities.** Remove `#[Entity]` / `#[Column]` attributes; the classes are already plain public-property records with application-assigned UUIDv7 ids. They stay as `Polaris\Model\*`.

**Schema.** Declare tables as data (one file per model), derived directly from the existing annotations and the 18 migrations:

```php
Schema::model('user', table: 'auth_users', fields: [
    Field::string('id', 36)->primary(),
    Field::string('email', 320)->unique(),
    Field::datetime('emailVerifiedAt')->nullable(),
    Field::string('passwordHash', 255)->nullable(),
    Field::string('status', 16)->default('active'),
    // …
]);
```

**Repositories.** Keep the 15 repository *classes* and their public methods (the domain depends on them). Reimplement each once over a single adapter interface:

```php
interface DatabaseAdapter {
    public function findOne(string $model, Where $where): ?array;
    public function findMany(string $model, Where $where, ?Query $q = null): array;
    public function insert(string $model, array $row): void;
    public function update(string $model, Where $where, array $data): int;
    public function delete(string $model, Where $where): int;
    public function count(string $model, Where $where): int;
    public function transaction(callable $fn): mixed;
}
```

Adapters: `pdo` first (Postgres, MySQL, SQLite, using the schema for column mapping), `cycle` for Univeros continuity (thin: wraps the existing `CycleRepository` mechanics), later Doctrine DBAL and Eloquent. `UnitOfWorkInterface` collapses into `transaction()` for the PDO path; the Cycle adapter keeps real UoW semantics.

**Migrations.** `polaris schema:export --target=sql:postgres|sql:mysql|sql:sqlite|laravel|doctrine|cycle` generates from the schema. The 18 existing Cycle migrations stay in the Univeros adapter for installed apps; new installs generate.

---

## 4. HTTP: from `Altair\Http` actions to a route manifest

The 56 `*Domain` classes are thin: read input, call a service, map exceptions to `{status, error, message}`, shape the body. That logic is portable; only two types are framework-bound.

Replace:
- `Altair\Http\Collection\InputCollection` → `Polaris\Http\Input` (same `get()`/validation surface, built from a PSR-7 request by adapters)
- `Altair\Http\Contracts\PayloadInterface` → `Polaris\Http\Result` (status + array body + headers; adapters render to PSR-7 / Laravel / Symfony responses)
- `AuthDomain` base → `Polaris\Http\Endpoint` base with the same `respond()`, `unprocessable()`, `client()` helpers

**The manifest.** The 52 files in `api/*.yaml` become the single source of routes. Add two fields to the existing format and load them at boot:

```yaml
endpoint:
  method: POST
  path: /auth/login
  auth: public
  rate_limit: login
  effect: write          # new: read | write | destructive
  receipt: false         # new: default true for write/destructive when the Agents plugin is on
domain:
  class: Polaris\Http\Auth\LoginEndpoint
```

Boot reads the manifest and registers routes; `polaris manifest` emits OpenAPI 3.1, the TS client, and the MCP tool list from the same files. Route registration in `Bootstrap/Routes.php` (currently hand-wired) is deleted.

**Middleware.** `Http/Middleware` is already PSR-15; it moves to `packages/psr15` unchanged except for helper imports. The Univeros adapter re-exports it with `MiddlewarePriority` ordering; Laravel/Symfony adapters wrap it in their own middleware/authenticator types.

---

## 5. Wiring without a container

`Polaris::create()` builds the object graph explicitly (services are constructor-injected and few). The seven `Bootstrap/*Bindings` classes become one `Wiring` class. The Univeros adapter keeps its container bindings and simply delegates to `Polaris::create()` then registers the resulting services — so a Univeros app continues to `config/modules.php` one line as today.

---

## 6. Target layout

```
packages/
  core/             Polaris\  — Contract, Model, Schema, Identity, Mfa, Token, Authorization,
                    Security, Event, Exception, Config, Http (endpoints + manifest loader), Wiring
  psr15/            Polaris\Psr15\ — RequestHandler, Middleware (moved from Http/Middleware)
  pdo/      Polaris\Pdo\
  cycle/    Polaris\Cycle\
  univeros/         Univeros\Polaris\ — Module.php, container bindings, Cycle migrations, priorities
  cli/              polaris init | doctor | schema:export | schema:diff | manifest
  testing/          in-memory DatabaseAdapter, fake mailer/SMS, fixed clock
api/                the 52 YAML specs (unchanged location; now loaded at runtime)
docs/               unchanged
```

`composer.json` of `univeros/polaris` becomes a metapackage requiring `polaris/core` + `polaris/cycle` + the Univeros glue, so existing users upgrade with no config change.

---

## 7. Order of work (tests green at each step)

1. **Fix the repo signals** — `AGENT.md` (still says implementation hasn't started), `composer.json` license (`proprietary` → MIT for core). Half a day.
2. **Monorepo skeleton** — `packages/`, Composer path repositories, CI running the existing suite from the new paths. One day.
3. **Relocate interfaces (§2)** — domain compiles framework-free. Run unit tests. Two to three days.
4. **Schema-as-data + `DatabaseAdapter` + `cycle`** — repositories rewritten over the adapter; Cycle adapter makes the existing integration tests pass unchanged. One week.
5. **`pdo` + in-memory adapter** — run the same integration tests against SQLite and Postgres. That set of tests is the start of the adapter conformance suite. One week.
6. **HTTP port (§4)** — `Input`/`Result`/`Endpoint`, manifest loader, `psr15` package. Endpoint tests run through PSR-15 with the in-memory adapter. One to two weeks.
7. **`Polaris::create()` wiring; Univeros adapter reduced to glue** — Univeros app boots on the new core. Two to three days.
8. **Slim demo app** — first non-Univeros consumer. Any friction here is an interface bug; fix it before Laravel. Two days.
9. **`polaris manifest`** — OpenAPI + TS client generation from `api/*.yaml`. One week.

Roughly six to eight weeks for one engineer who knows the code. Laravel and Symfony adapters follow in the design doc's M3.

---

## 8. Risks and how to handle them

- **Cycle-specific SQL** (`Cycle\Database\Injection\Fragment` appears once). Find and isolate it during step 4; it will need a per-dialect equivalent in the PDO adapter.
- **Unit of work semantics.** Some flows may rely on Cycle's deferred flush ordering. The PDO adapter uses explicit `transaction()`; verify token-rotation and invitation flows first, as they are the most order-sensitive.
- **Validation rules in YAML** (`rules: [required, email, "max:320"]`) are currently interpreted by the framework's validator. Core needs a tiny rule interpreter for the handful of rules used; count them before writing it — it is probably under a dozen.
- **Rate limiter and denylist stores** currently resolve framework cache bindings. Define `RateStore`/`Denylist` contracts with a PSR-16 default.
- **Do not add features during extraction.** Social login, passkeys, magic links, the Agents plugin all wait until step 8 passes. Extraction with feature work mixed in is how the 115 tests stop meaning anything.
