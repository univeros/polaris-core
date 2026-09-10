# Polaris framework adapters — working specification v1.0 (task 2)

**Repository:** `github.com/univeros/polaris-core`, the Polaris for PHP monorepo, after task 1 (the extraction, `docs/extraction/`).
**Baseline:** `main` after PR #12: `packages/{core,psr15,pdo,testing,cli}`, 52 endpoints in `packages/core/api/**/*.yaml`, 184 contract fixtures (1,201 request/response steps) replayed by the functional suite through `Polaris\Psr15\Pipeline`, 517 tests, CI green on PHP 8.3 and 8.4 against PostgreSQL plus the Slim demo job.
**Outcome:** Polaris runs, unchanged, inside Laravel, Symfony and Yii through one package each, wired from the framework's own configuration, database connection, cache, logger, events and console; every adapter is proven by the same functional suite and the same 184 fixtures replayed through the framework's HTTP kernel; a TypeScript client is generated from the manifest. `univeros/polaris` is not touched.

This document is written to be executed by an engineer or a coding agent. Every work package has acceptance criteria that can be checked mechanically. Decisions the spec leaves open go into `docs/adapters/decisions.md`, append only.

---

## 0. Ground rules

1. **No feature work on core.** An adapter wires, bridges and mounts; it adds no endpoint, claim, header, validation rule or default. Friction an adapter finds in core (a missing injection point, a constructor that reads the environment) is fixed in core in the adapter's work package, with its own entry in `decisions.md`; if the fix is observable, it goes into `docs/extraction/behaviour-changes.md` first, which stays the single register of behaviour changes.
2. **The HTTP contract stays frozen, and every adapter proves it.** The proof for an adapter is the functional suite (`packages/core/tests/Functional`, 21 classes) plus the 184 recorded fixtures replayed through the adapter's real HTTP kernel (§3.7). Status, body and every header Polaris sets must be identical. A framework may add the transport headers it adds to every response (`Date`, a computed `Cache-Control`, `Content-Length`); the adapter's harness declares that list explicitly, the comparison ignores exactly those names, and the list is logged in `decisions.md`. Where a framework makes the SAPI's default `Content-Type` explicit on a body-less response Polaris sent without one, the harness removes it before comparing, because every host sends that default on the wire. Nothing else is ignored.
3. **Tests green at every merged step.** Each work package ends with `composer qa` (phpcs, phpstan level 5, `bin/check-imports`, phpunit) green on the whole monorepo, new packages included, plus the adapter's functional run and its demo job in CI.
4. **One package per adapter, framework code only there.** `packages/laravel` (`Polaris\Laravel\`), `packages/symfony` (`Polaris\Symfony\`), `packages/yii` (`Polaris\Yii\`). `bin/check-imports` is extended: `Illuminate\` and `Laravel\` may appear only under `packages/laravel` and `examples/laravel`; `Symfony\Bundle\`, `Symfony\Component\{HttpKernel,HttpFoundation,DependencyInjection,Security,Config,Routing}\` only under `packages/symfony` and `examples/symfony` (core keeps `symfony/yaml` and `symfony/uid`, the CLI `symfony/console`); `Yiisoft\` only under `packages/yii` and `examples/yii`. `Altair\`, `Cycle\` and `Univeros\` stay forbidden everywhere.
5. **PHP 8.3 stays the floor.** Framework floors: Laravel `^13.0` (PHP `^8.3`), Symfony `^7.4 || ^8.0` (7.4 LTS keeps PHP 8.3; 8.x needs 8.4), Yii 3 (`yiisoft/yii-http ^1.1`). `declare(strict_types=1)`, PHPStan level 5, PSR-12, as in task 1.
6. **The framework's services are what Polaris gets.** The database is the framework's connection, handed to `Polaris\Pdo\PdoAdapter` as the PDO handle it already holds; the cache is the framework's (PSR-16 natively or through a bridge); the logger is the framework's PSR-3 logger; events go through the framework's dispatcher (Symfony's is PSR-14; Laravel's and Yii's get a bridge that runs the Polaris listeners and re-dispatches every event into the framework's own event system, so the host subscribes to Polaris events its usual way); the console is the framework's, carrying the `polaris/cli` commands.
7. **Same configuration, same defaults.** Every adapter maps its configuration to `Polaris\Wiring\Config` field by field (§3.1): the `auth` tree is `AuthConfig::fromArray()` with the keys of `docs/auth/configuration.md` §1, `rate_limits` is `RateLimitConfig::fromArray()`, secrets are the six `Secrets` values. No adapter invents a default core does not have.
8. **Every adapter ships a demo** under `examples/<framework>` that runs the shared walkthrough (`examples/walkthrough.sh`, the Slim script generalised) from a clean clone, in CI.
9. **Namespaces, attribution, scope** as in task 1: everything is `Polaris\*`; the author is the repository owner; if it is unclear whether something is in scope, it is not (§10).

---

## 1. Target layout

```
polaris-core/
  packages/
    core/ psr15/ pdo/ testing/ cli/      task 1, unchanged except decisions-logged friction fixes
    laravel/     polaris/laravel   Polaris\Laravel\   service provider, config, controller, guard, event bridge, mail bridge, artisan commands
    symfony/     polaris/symfony   Polaris\Symfony\   bundle, configuration, controller, route loader, authenticator, console commands
    yii/         polaris/yii       Polaris\Yii\       config plugin (di, params, routes), middleware, authentication method, console commands
    client-ts/   @polaris-auth/client (npm)           generated TypeScript client, not a Composer package
  examples/
    walkthrough.sh                 the shared walkthrough (register → verify → login → TOTP → MFA login → organization → switch-org)
    slim/  laravel/  symfony/  yii/   one minimal host per adapter; each bin/walkthrough.sh runs the shared script
  docs/adapters/                   this task: spec.md, decisions.md, README.md
```

The root `composer.json` requires the adapter packages through the existing `packages/*` path repository (pinned `0.1.x-dev`), so `composer qa` covers them; what a package's tests need beyond its own `require` (`orchestra/testbench-core`, a Symfony kernel, a Yii container) goes into the root `require-dev`. Each adapter package's `composer.json` is truthful on its own: it requires the framework packages its code imports and nothing it does not. The demos stay separate Composer projects on path repositories, as `examples/slim` is.

---

## 2. Dependency rules per package

| Package | May depend on |
|---|---|
| `laravel` | `core`, `psr15`, `pdo`, `cli`, `laravel/framework ^13.0`, `symfony/psr-http-message-bridge ^7.4 \|\| ^8.0`, `nyholm/psr7 ^1.8` |
| `symfony` | `core`, `psr15`, `pdo`, `cli`, `symfony/framework-bundle`, `symfony/security-bundle`, `symfony/psr-http-message-bridge` (all `^7.4 \|\| ^8.0`), `nyholm/psr7`; `doctrine/dbal` optional (a connection service is accepted, never required) |
| `yii` | `core`, `psr15`, `pdo`, `cli`, `yiisoft/yii-http`, `yiisoft/router`, `yiisoft/di`, `yiisoft/config`, `yiisoft/auth`, `yiisoft/yii-console`; `yiisoft/db` optional (a connection service is accepted, never required) |
| `client-ts` | npm only: `openapi-typescript` (dev), `openapi-fetch` (runtime), `typescript`, `vitest` (dev) |

Core, `psr15`, `pdo`, `testing` and `cli` keep the task 1 allow-lists (`docs/extraction/spec.md` §2). Version constraints on `symfony/console`, `symfony/yaml` and `symfony/uid` widen to `^7.0 || ^8.0` so an application already on Symfony 8 (PHP 8.4+) can require `polaris/cli` and `polaris/core`; the root keeps resolving 7.4 through its `platform.php` of 8.3.0.

---

## 3. The adapter contract

What every framework adapter provides, in the framework's idiom. Each item is an acceptance criterion of the adapter's work package.

### 3.1 Boot: one `Polaris` per process from the framework's configuration

`Polaris::create(new Config(...))` runs once, lazily, and the result is a shared service (`Polaris\Polaris`, `Polaris\Wiring\Graph`, `Polaris\Psr15\Pipeline`) in the framework's container. The configuration maps to `Config` as follows; every port accepts `null` (core default), a service id or class name (resolved from the container) or an object instance (used as is), so a host can build any port in code:

| Config key | `Config` field | Source |
|---|---|---|
| `secrets` | `secrets` | `app_key`, `jwt_private_key`, `jwt_public_key`, `jwt_kid`, `jwt_previous_public_key`, `jwt_previous_kid`; each value may instead come from `<key>_file` (a PEM path). Defaults read the environment names core reads (`APP_KEY`, `AUTH_JWT_*`, plus `*_FILE`). |
| `auth` | `auth` | `AuthConfig::fromArray()`, the `docs/auth/configuration.md` §1 keys; defaults `issuer` from `AUTH_ISSUER`, `audience` from `AUTH_AUDIENCE`, the two flags from `AUTH_ACCESS_TOKEN_DENYLIST` and `AUTH_PASSWORD_BREACH_CHECK`, as `EnvironmentConfig::auth()` does |
| `rate_limits` | `rateLimits` | `RateLimitConfig::fromArray()` |
| `database` | `database` | `null`: `PdoAdapter` over the framework's default connection; a connection name: that connection; an object: a `DatabaseAdapter` |
| `cache` | `cache` | `null`: the framework's default cache (PSR-16); a store name |
| `log` | `logger` | `null`: the framework's default logger (PSR-3); a channel name |
| `mailer`, `sms` | `mailer`, `sms` | `null` or `log`: core's `LogOtpMailer` / `LogSmsSender` on the framework logger; `mail`: the framework's mailer bridge (§3.5); a service id, class or object |
| `breach_check`, `clock`, `encrypter`, `metrics`, `totp`, `qr_codes`, `rate_store` | the same-named fields | `null` or a service |
| `path_prefix` | `pathPrefix` | the mount point of the routes, default `/` |
| `manifest_directory` | `manifestDirectory` | default: the package's `api/` |

The dispatcher is always the framework's (through the bridge where needed); `Polaris::listeners()` (audit log, notifications, metrics) are subscribed to it at boot. A host that passes its own PSR-14 dispatcher as `dispatcher` gets it as is, with the listeners subscribed only if it can subscribe them (the bridge can; a foreign dispatcher is the host's responsibility, documented).

### 3.2 Routes: every manifest route mounted under `path_prefix`

The adapter registers the manifest routes under the prefix, one framework route per endpoint where the framework keeps a route table (so its route listing shows them and nothing shadows the application's own routes when the prefix is `/`), all served by `Polaris\Psr15\Pipeline::handle()`: the framework request converted to PSR-7 (through `symfony/psr-http-message-bridge` where the framework is HttpFoundation-based; natively in Yii), the PSR-7 response converted back. The framework's own request middleware (sessions, cookies, CSRF, its rate limiter) is not applied to Polaris routes. The client IP the framework resolved (trusted proxies) is passed as `Attributes::IP_ADDRESS` before the pipeline runs, so `ClientContextMiddleware` and the rate-limit keys honour the host's proxy configuration. A wrong method on a Polaris route answers Polaris's 405 envelope; an unknown path is the application's 404.

### 3.3 Authentication for the host's own routes

A guard (Laravel), an authenticator (Symfony) or an authentication method (Yii) that verifies `Authorization: Bearer` with `Graph::tokenFactory()`, loads the user through `Graph::users()`, and exposes a `Polaris\<Fw>\Auth\PolarisUser` carrying the `Polaris\Model\User` and the verified `TokenInterface` (claims: organization, roles, permissions) in the framework's identity type. Its 401 for the host's routes is the framework's, not Polaris's envelope (documented: Polaris routes answer Polaris's 401; the host's routes answer the host's). No credentials login through it: login is the endpoint's job.

### 3.4 Schema and seed through the framework's migration tool

A console command writes the framework's migration artefact (Laravel: a migration file; Symfony and Yii: a `polaris:schema:create` / `polaris:schema:drop` command pair, since neither framework has one migration tool) whose `up` executes `SqlSchema::createAll()` for the connection's dialect through `PdoAdapter` and seeds the permission catalog and the system roles (`PermissionCatalogSeeder`), and whose `down` executes `SqlSchema::dropAll()`. No translation of the schema into the framework's schema builder: the SQL exporter is the single source and `schema:diff` proves parity (the demo's setup runs it).

### 3.5 Mail

`mailer: mail` binds the framework's mailer to `OtpMailerInterface`: the template name selects a plain-text template shipped by the adapter (`verify_email`, `password_reset`, `org_invite`, `otp_code`, `account_locked`, `password_changed`, `mfa_enrolled`, `mfa_factor_removed`, `recovery_code_used`, `recovery_codes_regenerated`), rendered with the context, with a subject per template; templates are publishable/overridable the framework's way. The default stays `log`, as in core: a host chooses delivery explicitly.

### 3.6 Console

The four `polaris/cli` commands are registered in the framework's console as `polaris:schema:export`, `polaris:schema:diff`, `polaris:manifest`, `polaris:doctor`, using the framework's connection and the adapter's `Secrets`/`AuthConfig` instead of `POLARIS_DSN` and the environment (the CLI commands gain optional providers for these; `--dsn` still overrides). Plus the adapter's own `polaris:install` (§3.4, and publishing the configuration file where the framework has that notion).

### 3.7 The proof: the functional suite through the framework's kernel

`FunctionalTestCase` (core's tests) gets a harness seam:

```php
namespace Polaris\Tests\Functional;

interface Harness
{
    /** Boots the host from this Config (the test's adapter, mailer, sms, dispatcher, secrets, auth). */
    public static function create(Config $config): static;
    public function graph(): Graph;
    public function handle(ServerRequestInterface $request): ResponseInterface;
    /** @return list<string> lower-case names of the transport headers the host adds to every response */
    public static function transportHeaders(): array;
}
```

`PipelineHarness` (core) wraps `Polaris::create()` + `Pipeline`, `transportHeaders()` empty: the task 1 run, unchanged. `FunctionalTestCase::boot()` instantiates the class named by `POLARIS_HARNESS` (default `PipelineHarness`); `Fixture`/`Normalizer` ignore the harness's transport headers on top of the volatile ones. Each adapter ships `Polaris\<Fw>\Tests\Harness` under `packages/<fw>/tests` (root `autoload-dev`), which boots a real application with the adapter installed, hands the test's `Config` objects to the adapter's configuration (§3.1 accepts instances), serialises the PSR-7 request to the wire form the framework parses (a JSON body is bytes, not a parsed array), pushes it through the framework's HTTP kernel, and converts the response back. CI runs, per adapter, on the same PostgreSQL service: `POLARIS_HARNESS=<class> vendor/bin/phpunit --testsuite functional` (the `functional` suite is `packages/core/tests/Functional` plus `tests/Contract`; the default run excludes it to avoid running those tests twice). `ContractCoverageTest` keeps asserting the 52 routes and more than 1,000 steps regardless of the harness. The 184 fixtures pass or the build fails; the ignored transport headers are logged in `decisions.md`.

The adapter's own behaviour (configuration mapping, the guard, the event and mail bridges, the install command) has unit tests under `packages/<fw>/tests`, in the default `composer qa` run.

### 3.8 The demo

`examples/<fw>`: a minimal host on the adapter with SQLite, a file "mailbox" for the walkthrough, `bin/setup` (env, RS256 keys, `polaris:install`, the migration, `schema:diff` clean, `polaris:doctor` ok) and `bin/walkthrough.sh` calling `examples/walkthrough.sh`. A CI job runs `composer install`, `bin/setup`, `bin/walkthrough.sh` on PHP 8.3, as the Slim job does. The demo README shows the host's integration in full; it should fit on one screen.

### 3.9 What an adapter must not do

Apply the framework's session, cookie or CSRF middleware to Polaris routes; alter status, body or Polaris headers; re-implement any `psr15` middleware; carry defaults that differ from core's; read secrets from a config file committed to the demo (they come from the environment or files the setup generates); depend on the framework's ORM.

---

## 4. Laravel (WP1)

`packages/laravel`, `Polaris\Laravel\`, `laravel/framework ^13.0`.

- **`PolarisServiceProvider`** (auto-discovered through `extra.laravel.providers`): merges `config/polaris.php` (publishable, tag `polaris-config`), registers `Polaris`, `Graph` and `Pipeline` as singletons built by `PolarisFactory` from `config('polaris')` per §3.1 (`database` null or a connection name → `PdoAdapter` over `DB::connection()->getPdo()`; `cache` → `Cache::store()`, PSR-16; `log` → `Log::channel()`), registers the routes in `boot()` (one named route per manifest endpoint, `polaris.auth.login` and so on, all to `PolarisController`, under `config('polaris.path_prefix')` with the middleware list from `config('polaris.middleware')`, default none), extends `Auth` with the `polaris` guard driver, registers the artisan commands, subscribes `Polaris::listeners()` to the event bridge, loads the mail views.
- **`PolarisController`**: `Illuminate\Http\Request` → PSR-7 through `PsrHttpFactory` (nyholm), `Attributes::IP_ADDRESS` = `$request->ip()`, `Pipeline::handle()`, PSR-7 → `Illuminate\Http\Response` through `HttpFoundationFactory`.
- **`Events\Dispatcher`** (PSR-14): runs the Polaris listeners, then `Illuminate\Contracts\Events\Dispatcher::dispatch($event)`, so `Event::listen(UserRegistered::class, ...)` works in the application.
- **`Auth\PolarisGuard`** (`Illuminate\Contracts\Auth\Guard`, built like the framework's `TokenGuard` with the current request refreshed) and **`Auth\PolarisUser`** (`Authenticatable` over `Polaris\Model\User` plus the token). `auth:polaris` is then the framework's middleware. Configuration: `auth.guards.polaris = ['driver' => 'polaris']`.
- **`Mail\OtpMailer`**: `Illuminate\Contracts\Mail\Mailer` with plain-text Blade views `polaris::mail.<template>` (namespace `polaris`, publishable, tag `polaris-views`).
- **`Console\InstallCommand`** (`polaris:install`): publishes the config and writes `database/migrations/<timestamp>_create_polaris_tables.php`, whose `up()`/`down()` call `Polaris\Laravel\Schema\PolarisSchema::create()` / `drop()` (§3.4; the migration runs outside the migrator's transaction because `PdoAdapter` opens its own). The four CLI commands are registered renamed with the application's connection, `Secrets` and `AuthConfig`.
- **Secrets**: `config/polaris.php` reads `POLARIS_APP_KEY`, falling back to Laravel's `APP_KEY` (its `base64:` value is at least 32 bytes; every Polaris key is HKDF-derived from it under a distinct context, so sharing the master key with Laravel's encrypter is acceptable and documented), and `AUTH_JWT_PRIVATE_KEY[_FILE]`, `AUTH_JWT_PUBLIC_KEY[_FILE]`, `AUTH_JWT_KID`, the previous-key pair, `AUTH_ISSUER`, `AUTH_AUDIENCE`.
- **`Tests\Harness`**: boots an application with `orchestra/testbench-core` (`Orchestra\Testbench\Foundation\Application::create()` with the provider), sets `config('polaris')` to the test's instances (`database`, `mailer`, `sms`, `dispatcher`, `secrets`, `auth`) and `cache` to the `array` store, converts the PSR-7 request to an `Illuminate\Http\Request` (JSON body serialised to bytes), runs `Illuminate\Contracts\Http\Kernel::handle()`, converts the response back with `PsrHttpFactory`. `transportHeaders()` lists what HttpFoundation adds (`cache-control` at least; the run decides, `decisions.md` records).
- **`examples/laravel`**: `composer.json` (framework, adapter through the path repository), `artisan`, `bootstrap/app.php` (`Application::configure()`), `public/index.php`, `config/polaris.php`, `config/auth.php` (the guard), `config/database.php` (SQLite at `database/polaris.sqlite`), `.env.example`, `src/FileMailer.php` (the JSON-lines mailbox), `bin/setup`, `bin/walkthrough.sh`, README.
- **CI**: the `qa` matrix gains the step `POLARIS_HARNESS=Polaris\Laravel\Tests\Harness vendor/bin/phpunit --testsuite functional`; a `demo-laravel` job mirrors the Slim one.

---

## 5. Symfony (WP2)

`packages/symfony`, `Polaris\Symfony\`, `symfony/framework-bundle ^7.4 || ^8.0`.

- **`PolarisBundle`** (`AbstractBundle`): `configure()` declares the tree of §3.1 under `polaris:` (`secrets`, `auth`, `rate_limits`, `database: { dsn, user, password }` or `database: { connection: <service id> }` accepting a PDO or a Doctrine DBAL `Connection` (`getNativeConnection()`), `cache` (a PSR-16 service id, default a `Psr16Cache` over `cache.app`), `logger`, `mailer`, `sms`, the ports, `path_prefix`); `loadExtension()` registers `Polaris`, `Graph`, `Pipeline` (nyholm PSR-17 + the bridge), `PolarisController`, the route loader, the authenticator, the event subscriber, the console commands.
- **Routing**: a route loader of type `polaris` (`config/routes/polaris.yaml`: `polaris: { resource: ., type: polaris, prefix: /auth-api }`) yielding one catch-all route to `PolarisController` (`Request` → PSR-7 → `Pipeline::handle()` → `Response`; `Attributes::IP_ADDRESS` = `$request->getClientIp()`).
- **Events**: `symfony/event-dispatcher` is PSR-14; an `EventSubscriberInterface`-free registration subscribes `Polaris::listeners()` through `$dispatcher->addListener(<event class>, ...)` for each event class the manifest lists (`docs/auth/events.md`), so `#[AsEventListener(UserRegistered::class)]` works in the application.
- **Security**: `Security\PolarisAuthenticator` (`AbstractAuthenticator`) for `security.firewalls.<name>.custom_authenticators`, `Security\PolarisUser` (`UserInterface`) with the token; roles `ROLE_USER` plus the Polaris roles as `ROLE_POLARIS_<ROLE>` (a mapping, not a policy).
- **Console**: `polaris:schema:create`, `polaris:schema:drop`, and the four CLI commands renamed, tagged `console.command`.
- **`Tests\Harness`**: a `Kernel` with `MicroKernelTrait`, FrameworkBundle + PolarisBundle, configuration in code with the test's instances registered as synthetic services; `$kernel->handle()`; the bridge for both directions.
- **`examples/symfony`**: `src/Kernel.php`, `config/{bundles.php,packages/polaris.yaml,routes/polaris.yaml}`, `public/index.php`, `bin/console`, SQLite DSN, `bin/setup`, `bin/walkthrough.sh`, README.

---

## 6. Yii (WP3)

`packages/yii`, `Polaris\Yii\`, Yii 3 (`yiisoft/yii-http ^1.1`, `yiisoft/router ^4.0`, `yiisoft/di`, `yiisoft/config`, `yiisoft/auth`, `yiisoft/yii-console`).

- **Config plugin** (`extra.config-plugin`): `config/di.php` (the `Polaris`, `Graph`, `Pipeline` definitions from `params['polaris']`, §3.1; `database` accepts a PDO service, a `yiisoft/db` connection (`getPDO()`), or a DSN), `config/params.php` (the defaults), `config/routes.php` (one catch-all `Route::methods([...], '{path:.*}')` group under the prefix whose middleware is `Pipeline::middleware()` and whose action is `Pipeline::handler()`; PSR-15 native, no bridge), `config/di-console.php` and `config/params-console.php` (the commands).
- **Events**: `yiisoft/event-dispatcher` is PSR-14; the plugin's `config/events.php` maps each Polaris event class to the listeners, the Yii way.
- **Auth**: `Auth\PolarisAuthenticationMethod` (`Yiisoft\Auth\AuthenticationMethodInterface`, bearer) returning `Auth\PolarisIdentity` (`IdentityInterface` with the user and the token) for `yiisoft/auth`'s `Authentication` middleware on the host's routes.
- **Console**: `polaris/schema:create`, `polaris/schema:drop`, and the four CLI commands.
- **`Tests\Harness`**: a `Yiisoft\Di\Container` built from the plugin's config arrays with the test's instances as definitions; `Yiisoft\Yii\Http\Application::handle()`.
- **`examples/yii`**: a `yiisoft/app`-shaped minimal host: `config/`, `public/index.php`, `yii`, `bin/setup`, `bin/walkthrough.sh`, README.

---

## 7. TypeScript client (WP4)

`packages/client-ts`, npm `@polaris-auth/client` (the scope is the owner's decision, `target-design.md` §9; the name is a placeholder until then, logged).

- **Generation, not authoring:** `bin/polaris manifest --format=openapi > openapi.json`; `openapi-typescript` turns it into `src/schema.d.ts` (checked in, drift-checked in CI: regenerate and `git diff --exit-code`); `src/index.ts` (hand-written, small) wraps `openapi-fetch` with `createClient({ baseUrl, token })` and a `withToken()` helper, nothing more (no refresh loop, no storage: those are application policy).
- **Proof:** `npm run generate && npm run typecheck && npm test` in a CI job; the test starts the Slim demo and runs register → verify → login → me through the client, so the types are checked against the live contract.
- `polaris manifest --format=openapi` gains whatever the generator needs to type the responses (it types requests from the manifest rules already); response typing comes from the `output.example` shapes in the specs as JSON-schema-by-example, a documented approximation, unless the manifest grows explicit response schemas, which is out of scope.

---

## 8. Work packages

| WP | Title | Scope | Acceptance criteria |
|---|---|---|---|
| **WP0** | Preparation | Split workflow, per-package READMEs, `api/` inside `polaris/core` (PR #12); this spec, `docs/adapters/` (PR #13) | `composer qa` green; `bin/polaris manifest` loads from the package; the split job is skipped without `SPLIT_ORG` |
| **WP1** | Laravel | §4 plus the harness seam (§3.7), the shared walkthrough (§3.8), the `check-imports` extension (§0.4), the constraint widening (§2), the CLI providers (§3.6) | (a) `composer validate --strict packages/laravel/composer.json`; (b) `bin/check-imports` passes and fails on an `Illuminate\` import planted outside `packages/laravel` (unit test of the script); (c) `POLARIS_HARNESS=Polaris\Laravel\Tests\Harness vendor/bin/phpunit --testsuite functional` green in CI on PostgreSQL: 184 fixtures, 1,201 steps through Laravel's HTTP kernel, transport headers logged; (d) `POLARIS_HARNESS` unset: the default run is unchanged (517 tests plus the adapter's unit tests); (e) `examples/laravel`: `composer install && bin/setup && bin/walkthrough.sh` green in CI, where `bin/setup` runs `php artisan polaris:install`, `php artisan migrate`, `php artisan polaris:schema:diff` (no difference) and `php artisan polaris:doctor` (ready); (f) `packages/laravel/tests` cover the config mapping (every §3.1 key), the guard (valid, invalid and missing bearer), the event bridge and the install command; (g) no core change without a `decisions.md` entry |
| **WP2** | Symfony | §5 | (a)–(g) as WP1 for `packages/symfony`, `Polaris\Symfony\Tests\Harness`, `examples/symfony` |
| **WP3** | Yii | §6 | (a)–(g) as WP1 for `packages/yii`, `Polaris\Yii\Tests\Harness`, `examples/yii` |
| **WP4** | TypeScript client | §7 | `npm ci && npm run generate && git diff --exit-code src/schema.d.ts && npm run typecheck && npm test` green in CI against the Slim demo |

Branch names: `adapters/wp0` (split across PRs #12 and #13 as noted), `adapters/wp1` … `adapters/wp4`, one at a time, each merged before the next starts (stacking while CI runs is fine).

---

## 9. Definition of done (task 2)

- Three adapter packages, each proving the frozen contract through its own HTTP kernel in CI; framework namespaces isolated by `bin/check-imports`; every adapter's demo green in CI from a clean clone.
- The `polaris/cli` commands reachable from each framework's console with the framework's connection.
- The TypeScript client generated from the manifest, drift-checked, smoke-tested against the live contract.
- `docs/adapters/decisions.md` complete; `docs/extraction/behaviour-changes.md` unchanged, or every new row justified by a core friction fix.
- The adapters join the packages' version line (`v0.1.0` tags are the owner's, with the split repositories).
- `univeros/polaris` is unchanged.

---

## 10. Explicitly out of scope (later tasks)

The plugin contract (`target-design.md` §3.2) and everything built on it: the Agents plugin, the Cloud connect plugin, social login, passkeys, magic links (task 3, its own spec) · dedicated `polaris/doctrine` or `polaris/eloquent` database adapters (the frameworks' connections are used through `polaris/pdo`; a dedicated adapter only if friction proves the need, logged) · React/Vue hooks for the client · any change to token formats, session semantics, the 52 endpoints, or `docs/auth/api-reference.md` · a Univeros or Cycle adapter · **any change to `univeros/polaris`**.
