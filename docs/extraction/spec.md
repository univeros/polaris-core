# Polaris core extraction — working specification v1.0

**Repository:** a new repository `github.com/univeros/polaris-core` (local folder `~/projects/polaris-core`), seeded from a copy of `univeros/polaris` at v1.0.0 with its git history. **`univeros/polaris` itself is not modified**: it stays the Univeros module, in its own repo, with its own releases.  
**Baseline:** tag v1.0.0, commit 17ec933, 252 source files, 115 test files, 52 endpoint specs in `api/`, 18 migrations.  
**Outcome:** `polaris/core` runs Polaris's full 1.0 feature set with no dependency on `Altair\*`, Cycle, or Univeros; a Slim app runs the same endpoints through PSR-15 against SQLite/Postgres via PDO. The 115 tests are carried over and pass (database tests re-based on PDO), plus new adapter, PSR-15, and contract-freeze tests.

This document is written to be executed by an engineer or a coding agent. Every work package has acceptance criteria that can be checked mechanically.

---

## 0. Ground rules

1. **No feature work.** No new endpoints, plugins, or behaviour changes. If a behaviour must change to remove a dependency, record it in `docs/extraction/behaviour-changes.md` with the reason.
2. **Tests stay green at every merged step.** Each work package ends with `composer qa` (cs + stan + test) passing on the whole monorepo.
3. **Public HTTP contract is frozen.** Every request/response shape in `api/*.yaml` and `docs/auth/api-reference.md` is unchanged. A recorded-fixture test (WP6) enforces it.
4. **Namespaces.** Everything in the new repository is `Polaris\*`. There is no compatibility layer with `Univeros\Polaris\*`, because `univeros/polaris` continues to exist unchanged for Univeros hosts.
5. **PHP 8.3+**, `declare(strict_types=1)`, PHPStan level unchanged from 1.0.
6. **Nothing in the repository may import** `Altair\`, `Cycle\`, `Univeros\`, or any framework namespace. Enforced by a PHPStan rule / `composer qa` grep in WP1. (A Cycle adapter and a Univeros adapter are possible later packages, not part of this task.)

---

## 1. Target layout

```
polaris-core/                  (github.com/univeros/polaris-core, local ~/projects/polaris-core)
  composer.json                # monorepo root: path repos, scripts (qa runs every package)
  packages/
    core/                      polaris/core        Polaris\
    psr15/                     polaris/psr15       Polaris\Psr15\
    pdo/                       polaris/pdo         Polaris\Pdo\
    testing/                   polaris/testing     Polaris\Testing\
    cli/                       polaris/cli         Polaris\Cli\        (bin/polaris)
  api/                         52 YAML specs — same path as the original, now loaded at runtime
  docs/                        docs/auth copied from the original; docs/extraction added
  examples/slim/               WP8 demo app
  tests/                       split per package (WP1)
```

The 18 Cycle migrations are not carried over; `polaris schema:export` replaces them. Later packages (`polaris/laravel`, `polaris/symfony`, `polaris/yii`, `polaris/doctrine`, `polaris/eloquent`, and, only if ever wanted, `polaris/cycle` and `polaris/univeros`) join this monorepo.

`packages/core/src` layout:

```
Contract/      interfaces (§3)                 Model/        plain records (ex-Entity)
Schema/        schema-as-data + field types    Repository/   15 repositories over DatabaseAdapter
Identity/ Mfa/ Token/ Authorization/ Security/ Event/ Exception/ Config/ Support/   (moved, imports fixed)
Http/          Input, Result, Endpoint base, endpoints (ex-*Domain), Manifest loader, Validation
Wiring/        Polaris::create() object graph
```

---

## 2. Dependency rules per package

| Package | May depend on |
|---|---|
| `core` | `psr/http-message`, `psr/http-server-middleware`, `psr/event-dispatcher`, `psr/simple-cache`, `psr/clock`, `psr/log`, `psr/http-client`, `symfony/uid`, `spomky-labs/otphp`, `endroid/qr-code`, `lcobucci/jwt` (or the JWT lib already used behind `LcobucciTokenParser`), `symfony/yaml` (manifest) |
| `psr15` | `core`, PSR-7/15/17 interfaces |
| `pdo` | `core`, `ext-pdo` |
| `testing` | `core` |
| `cli` | `core`, `symfony/console` |

---

## 3. Contracts to own (WP2)

Copy into `Polaris\Contract` with the **same method names and semantics** the domain already uses; do not redesign them in this task.

### 3.1 Persistence
Usage counts in the domain: `persist` 55, `flush` 41, `findBy` 34, `find` 33, `findOneBy` 25, `remove` 9, `findAll` 7.

```php
namespace Polaris\Contract;

/** @template T of object */
interface RepositoryInterface
{
    /** @return T|null */          public function find(string $id): ?object;
    /** @return T|null */          public function findOneBy(array $criteria): ?object;
    /** @return list<T> */         public function findBy(array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array;
    /** @return list<T> */         public function findAll(): array;
    /** @param T $entity */        public function persist(object $entity): void;
    /** @param T $entity */        public function remove(object $entity): void;
}

interface UnitOfWorkInterface
{
    public function flush(): void;
    /** @template R  @param callable(): R $fn  @return R */
    public function transaction(callable $fn): mixed;
}
```

If the Altair versions have extra methods the domain doesn't call, leave them out. `criteria` is `column => scalar|list<scalar>|null` (equality / IN / IS NULL) — that is all the domain uses; verify in WP2 and note any exception.

### 3.2 Tokens
Own the JWT contracts the `Token/` layer implements: `TokenInterface`, `TokenGeneratorInterface`, `TokenParserInterface`, `TokenValidatorInterface`, `TokenFactoryInterface`, `TokenConfigurationInterface`, `IdentityProviderInterface`. Signatures copied verbatim from usage. `LcobucciTokenParser` is reimplemented inside `core/Token` (it is a thin wrapper around the JWT library).

### 3.3 Security
`EncrypterInterface` (+ `DecryptException`). Core ships a default `SodiumEncrypter` (XChaCha20-Poly1305 via libsodium) keyed from `Secrets`; the Univeros adapter may bind its own.

### 3.4 Existing ports (already framework-free, keep)
`BreachedPasswordCheckInterface`, `OtpMailerInterface`, `PasswordHasherInterface`, `PermissionContributorInterface`, `QrCodeRendererInterface`, `SmsSenderInterface`, `TotpProviderInterface`.

### 3.5 New ports introduced by extraction
```php
interface RateStore   { public function hit(string $key, int $limit, int $windowSeconds): RateResult; }      // default: PSR-16 backed
interface Denylist    { public function add(string $jti, int $ttl): void; public function has(string $jti): bool; } // default: PSR-16 backed
interface ClockInterface extends \Psr\Clock\ClockInterface {}                                               // default: SystemClock
```
Replace every direct framework cache/clock lookup with these.

---

## 4. Persistence (WP3, WP4)

### 4.1 Models
`Entity/*` → `Model/*`. Remove `#[Entity]`/`#[Column]` attributes; keep classes, properties, constants, and behaviour. Ids stay application-assigned UUIDv7.

### 4.2 Schema as data
One definition per model in `core/src/Schema/Definitions/`, derived from the removed attributes and the 18 migrations:

```php
final class UserSchema {
    public static function define(): Model {
        return Model::table('auth_users', User::class, [
            Field::string('id', 36)->primary(),
            Field::string('email', 320),
            Field::datetime('emailVerifiedAt', column: 'email_verified_at')->nullable(),
            Field::string('passwordHash', 255, column: 'password_hash')->nullable(),
            // … every column, with type, length, nullability, default, index/unique
        ])->unique(['email']);
    }
}
```
`Schema::all()` returns every model. Field types: `string(n)`, `text`, `int`, `bool`, `datetime`, `json`. Property↔column mapping lives here, nowhere else.

### 4.3 DatabaseAdapter
```php
namespace Polaris\Contract;

interface DatabaseAdapter
{
    public function findOne(string $table, array $criteria): ?array;
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array;
    public function insert(string $table, array $row): void;
    public function update(string $table, array $criteria, array $data): int;
    public function delete(string $table, array $criteria): int;
    public function count(string $table, array $criteria): int;
    public function transaction(callable $fn): mixed;
    public function dialect(): Dialect;   // postgres | mysql | sqlite | mssql
}
```
Rows are `column => value` arrays; the generic repository maps rows↔models using the schema.

### 4.4 Repositories
The 15 classes in `Persistence/` become `Repository/*Repository`, each `extends GenericRepository` (implements `RepositoryInterface`) parameterised by its schema model. `persist()` does insert-or-update by primary key (track identity in-request with a simple identity map so `persist` twice doesn't double-insert). `remove()` deletes by id. `UnitOfWork::flush()` becomes a no-op for the PDO path (writes are immediate inside `transaction()`); order-sensitive flows are covered by tests (§4.6).

Custom query methods that currently exist on repositories (if any beyond the base) are kept and implemented over `findMany`/`findOne`. The single `Cycle\Database\Injection\Fragment` usage is isolated and reimplemented per dialect.

### 4.5 Adapters
- **`pdo`**: PDO for Postgres, MySQL, SQLite. Prepared statements only. `transaction()` uses savepoints when nested.
- **`testing`**: `InMemoryAdapter` implementing `DatabaseAdapter` over arrays, supporting the criteria semantics; `FakeMailer`, `FakeSms`, `FixedClock`, `RecordingDispatcher`.

### 4.6 Adapter conformance tests
A single PHPUnit test suite `tests/AdapterConformance/` parameterised over adapters (in-memory, SQLite, Postgres when `POLARIS_TEST_DSN_PG` is set). It exercises every repository operation and these order-sensitive flows end to end at the service level: register→verify→login, refresh rotation and reuse detection (family revocation), invitation create→accept, MFA enroll→confirm→verify, org role change with last-owner protection. This suite is the seed of the public adapter conformance suite.

---

## 5. HTTP layer (WP5, WP6)

### 5.1 Types
```php
namespace Polaris\Http;

final class Input        // replaces Altair\Http\Collection\InputCollection
{  public function get(string $key, mixed $default = null): mixed; public function has(string $key): bool;
   public function all(): array; public function attribute(string $key): mixed;   // route params, token, client context
   public static function fromServerRequest(\Psr\Http\Message\ServerRequestInterface $r, array $routeParams): self; }

final class Result       // replaces PayloadInterface
{  public function __construct(public readonly int $status, public readonly array $body = [], public readonly array $headers = []) {} }

abstract class Endpoint  // replaces AuthDomain base; same helper names
{  protected function respond(int $status, array $output): Result;
   protected function unprocessable(array $errors): Result;
   protected function unauthorized(): Result;
   protected function client(Input $input): ClientContext;
   protected function isEmail(string $email): bool;
   protected function token(Input $input): ?TokenInterface;
   protected function mfaTicket(Input $input): ?MfaTicket;
   abstract public function __invoke(Input $input): Result; }
```
Each `Http/**/*Domain.php` → `Http/**/*Endpoint.php` with imports swapped and nothing else changed. Body shapes are untouched.

### 5.2 Manifest as the route source
`api/*.yaml` is loaded by `Polaris\Http\Manifest\Loader` (cached, validated against `api/schema.json` added in this WP). `Bootstrap/Routes.php` is deleted. The 52 specs gain:

```yaml
endpoint:
  effect: read | write | destructive     # new, required
  receipt: true|false                    # new, optional; default true for write/destructive
domain:
  class: Polaris\Http\Auth\LoginEndpoint # namespace updated
```
A test asserts: every spec's `domain.class` exists and extends `Endpoint`; every `Endpoint` class is referenced by exactly one spec; `method+path` are unique; `rate_limit` names exist in `RateLimitConfig`.

Assignment of `effect` per endpoint: `GET` and `/auth/me`, `sessions` list, `mfa/factors` list, `orgs` reads, `permissions/list`, `jwks` → `read`. Deletes, `logout-all`, `users/delete`, `orgs/delete`, `role-delete`, `member-remove`, `session-revoke`, `factor-delete`, `recovery-codes/regenerate` → `destructive`. Everything else → `write`. Record the table in `docs/extraction/effects.md`.

### 5.3 Validation
The YAML `rules` in use: `required` (52), `max:n` (11), `optional` (7), `email` (7), `string` (4), `password_policy` (3), `in:a,b` (3), `regex:` (2), `e164` (1), `suspended` (1 — check meaning). Implement `Polaris\Http\Validation\Rules` covering exactly these; `Input` validation is invoked by the handler before the endpoint runs, producing the same 422 `validation_failed` body as today. `sensitive: true` fields are never logged or echoed (used later by the Cloud plugin).

### 5.4 Middleware
`Http/Middleware/*` moves to `packages/psr15/src/Middleware/` unchanged in behaviour. Framework helpers they used (`BearerTokenExtractor`, `UnauthorizedResponder`, priority constants) are re-homed in `psr15`. Order (as today): ClientContext → AuthRateLimit → Token authentication → Denylist → MfaToken → StepUp → Authorization → AuthenticatedRateLimit.

### 5.5 PSR-15 handler
`Polaris\Psr15\RequestHandler` : routes by manifest (method + path with `{param}`), builds `Input`, runs validation, invokes the endpoint, renders `Result` to PSR-7 via a PSR-17 factory. Path prefix configurable (default `/`). Unknown route → 404 JSON in the existing error envelope.

### 5.6 Contract freeze test
`tests/Contract/`: for every spec, a recorded request/response fixture generated **before** WP5 from the 1.0 code (via the Univeros functional harness), replayed after through PSR-15 + in-memory adapter. Differences fail the build. Timestamps, ids, and tokens are normalised.

---

## 6. Wiring (WP7)

```php
$polaris = Polaris::create(new Config(
    secrets:  Secrets::fromEnvironment($env),        // unchanged class
    auth:     AuthConfig::fromArray($array),         // unchanged class
    database: new PdoAdapter($pdo),
    mailer:   $mailer,   sms: $sms,   breachCheck: $hibp,   cache: $psr16,   clock: null, dispatcher: $psr14, logger: $psr3,
));
$polaris->handler();     // PSR-15 RequestHandlerInterface (requires polaris/psr15)
$polaris->middleware();  // ordered list of MiddlewareInterface
$polaris->api();         // service accessors: identity(), mfa(), tokens(), organizations(), authorization()
$polaris->schema();      // Schema::all()
$polaris->manifest();    // loaded manifest
```
The seven `Bootstrap/*Bindings` classes collapse into `Wiring/Graph.php` (explicit construction, no container). `Module.php` and everything implementing Univeros module contracts is removed from this repository; that code lives on, unchanged, in `univeros/polaris`.

---

## 7. CLI (WP7)
`bin/polaris` with: `schema:export --target=sql:postgres|sql:mysql|sql:sqlite|laravel|doctrine|cycle`, `schema:diff --dsn=`, `manifest --format=json|openapi`, `doctor` (config, secrets, keys, DB connectivity, manifest validation). OpenAPI 3.1 output is generated from the manifest + `Input` rules; the TS client generator is **out of scope** for this task (next task).

---

## 8. Work packages

| WP | Title | Scope | Acceptance criteria |
|---|---|---|---|
| **WP0** | Seed the repository | `git clone` `univeros/polaris` at v1.0.0 into `~/projects/polaris-core` and re-point `origin` to the new remote (history preserved); replace `AGENT.md`; root `composer.json` → `polaris/monorepo` (root is never published), license MIT; add `docs/extraction/`; CI runs `composer qa` | `composer qa` green on the seeded repo; `univeros/polaris` untouched |
| **WP1** | Monorepo skeleton | `packages/*` with composer.json each; root path repositories; tests split per package; PHPStan rule forbidding framework imports; CI runs `composer qa` for all | All 115 tests pass from new locations (tests that need Univeros may be skipped with a tracked list, emptied by WP4/WP7); forbidden-import check runs (advisory until WP5, then blocking) |
| **WP2** | Own the contracts | §3.1–3.5 interfaces in `Polaris\Contract`; repoint imports in Identity/Mfa/Token/Authorization/Security/Config; `LcobucciTokenParser` → core; `SodiumEncrypter` default; `RateStore`/`Denylist`/`Clock` ports | `grep -r "Altair\\\\" packages/core/src` returns nothing except `Persistence`/`Http`; unit suites (Security, Token, Identity, Mfa, Authorization, Config) green |
| **WP3** | Models + schema | `Model/*`, `Schema/Definitions/*`, `Schema::all()`, `GenericRepository`, `Repository/*` over `DatabaseAdapter`, `InMemoryAdapter` in `testing` | Adapter conformance suite green on in-memory; `Entity/` and `Persistence/` deleted from core |
| **WP4** | PDO adapter | `pdo` (sqlite, mysql, postgres); `schema:export`; the 17 `DatabaseTestCase` tests re-based on the PDO adapter with SQLite | Conformance suite green on in-memory, SQLite, Postgres (CI service container); `DatabaseTestCase` suite green on PDO; Fragment usage reimplemented |
| **WP5** | HTTP port | `Input`/`Result`/`Endpoint`; 56 endpoints renamed and re-imported; `Validation\Rules`; manifest loader + `api/schema.json` + `effect`/`receipt` fields; `Routes.php` deleted | Manifest tests (§5.2) green; `grep -r "Altair\\\\" packages/core/src` returns nothing; forbidden-import check blocking |
| **WP6** | PSR-15 + contract freeze | `psr15` package: handler, middleware, responders; contract fixtures recorded from the **original `univeros/polaris` 1.0** functional harness (in `~/projects/polaris`), committed here, and replayed through PSR-15 | All 52 fixtures identical; `FunctionalTestCase` (21) ported to run through PSR-15 + in-memory adapter and green |
| **WP7** | Wiring + CLI | `Polaris::create()`, `Wiring/Graph`; `Module.php`, `Bootstrap/*`, and every Univeros module contract removed; `bin/polaris` commands | Zero `Altair`/`Cycle`/`Univeros` imports anywhere in the repository (blocking check); `polaris doctor` passes; `schema:diff` clean against a database migrated by the original 1.0 (schema parity) |
| **WP8** | Slim demo | `examples/slim`: Slim 4 app + `pdo` (SQLite) + `psr15`, `.env.example`, README with curl walkthrough of register→verify→login→MFA→org | Walkthrough executes end to end from a clean clone in under 10 minutes; any interface friction found here is fixed in core before closing |

Estimated total: six to eight weeks for one engineer familiar with the codebase; WP3–WP4 and WP5–WP6 are the two heavy pairs. Suggested branch names: `extract/wp0` … `extract/wp8`, each merged before the next starts.

---

## 9. Definition of done (task 1)

- Zero framework imports anywhere in the repository (CI-enforced); all suites green.
- Adapter conformance suite green on in-memory, SQLite, Postgres.
- 52 contract fixtures recorded from the original 1.0 are identical through PSR-15.
- Slim demo runs from a clean clone in under 10 minutes.
- `docs/extraction/` contains `behaviour-changes.md` (ideally empty), `effects.md`, `decisions.md`.
- `univeros/polaris` is unchanged.
- First tags `v0.1.0` on `polaris/core`, `polaris/psr15`, `polaris/pdo`, `polaris/testing`, `polaris/cli`.

---

## 10. Explicitly out of scope (next tasks)

Laravel/Symfony/Yii adapters · a Cycle adapter or a Univeros adapter (only relevant if `univeros/polaris` 2.0 is ever rebuilt on core) · social login · passkeys · magic links · TS client generation · Agents plugin · Cloud connect plugin · any change to token formats or session semantics · **any change to `univeros/polaris`** · website relaunch (only the docs switcher scaffolding happens alongside this task).
