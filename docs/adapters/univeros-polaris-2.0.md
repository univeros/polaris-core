# `univeros/polaris` 2.0: what the owner applies in that repository

Prepared in `polaris-core` on 2026-09-10 (spec §6b, `decisions.md`), never applied from here: `univeros/polaris`
is a different repository and this one does not modify it. It records the owner's decisions of that day, the 2.0
`composer.json`, the module's design as it was verified against `univeros/framework` 2.5.1 (file paths are the
framework's), the recipe that proves the contract through Relay, and the CHANGELOG/UPGRADE text.

## The decisions that apply there

1. 2.0 is a new major of `univeros/polaris` built on `polaris/core`, `polaris/psr15`, `polaris/pdo` and
   `polaris/cli`, like any application; 1.x installations are not touched and keep working.
2. Routes: a `PolarisMiddleware` ahead of the framework's `ExceptionHandlerMiddleware` serves every manifest
   path through `Polaris\Psr15\Pipeline::handle()`; the Polaris routes are not in the FastRoute table.
3. No compatibility encrypter and no re-encryption path: TOTP secrets encrypted by 1.x are not readable by 2.0;
   users re-enrol their TOTP factors (the UPGRADE text says so).
4. Migrations: one Cycle migration calling `Polaris\Pdo\SchemaInstaller`, so `bin/altair db:migrate` installs
   Polaris and `polaris schema:diff` proves parity.

## `composer.json`

```json
{
    "name": "univeros/polaris",
    "description": "Polaris for PHP as a Univeros module: authentication, MFA/OTP, organizations and RBAC on polaris/core.",
    "type": "library",
    "license": "proprietary",
    "keywords": ["univeros", "altair", "polaris", "authentication", "mfa", "otp", "totp", "rbac", "users", "jwt"],
    "homepage": "https://univeros.io",
    "support": {
        "issues": "https://github.com/univeros/polaris/issues",
        "source": "https://github.com/univeros/polaris"
    },
    "require": {
        "php": ">=8.3",
        "laminas/laminas-diactoros": "^3.0",
        "polaris/cli": "^0.1",
        "polaris/core": "^0.1",
        "polaris/pdo": "^0.1",
        "polaris/psr15": "^0.1",
        "psr/http-message": "^1.1 || ^2.0",
        "psr/http-server-middleware": "^1.0",
        "univeros/cli": "^2.5",
        "univeros/container": "^2.5",
        "univeros/http": "^2.5",
        "univeros/module": "^2.5",
        "univeros/persistence": "^2.5"
    },
    "require-dev": {
        "httpsoft/http-message": "^1.1",
        "phpstan/phpstan": "^2.1",
        "phpunit/phpunit": "^12.5",
        "polaris/testing": "^0.1",
        "squizlabs/php_codesniffer": "^3.13.6"
    },
    "autoload": {
        "psr-4": {
            "Univeros\\Polaris\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Univeros\\Polaris\\Tests\\": "tests/",
            "Polaris\\Tests\\": "vendor/polaris/core/tests/"
        }
    },
    "scripts": {
        "cs": "phpcs",
        "cs-fix": "phpcbf",
        "stan": "phpstan analyse",
        "test": "phpunit",
        "test:contract": [
            "@putenv POLARIS_HARNESS=Univeros\\Polaris\\Tests\\Harness",
            "phpunit --testsuite functional"
        ],
        "qa": ["@cs", "@stan", "@test", "@test:contract"]
    },
    "config": {
        "sort-packages": true,
        "platform": {
            "php": "8.3.0"
        }
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

`laminas/laminas-diactoros` is what the framework's `HttpMessageConfiguration` uses, so the pipeline's response
factory is the framework's. `polaris/testing` and `httpsoft/http-message` are what `polaris/core`'s test suite
needs. The `polaris/*` constraints follow the first tags.

## What the 1.0 tree becomes

Everything that moved into `polaris/core` is deleted: `src/{Authorization,Config,Contracts,Entity,Event,
Exception,Identity,Maintenance,Mfa,Notification,Observability,Persistence,Security,Support,Token}`, the
endpoint classes under `src/Http`, `database/migrations`, `api/`, and their tests; `polaris/core` carries all of
it, contract-frozen. What stays is the framework glue, rewritten on the `Polaris\` services:

```
src/Module.php                       ModuleInterface, MiddlewareProviderInterface, MigrationDirectoriesProviderInterface
src/Http/PolarisMiddleware.php       the Polaris routes, ahead of the exception handler
src/Http/BearerTokenExtractor.php    kept from 1.0 (src/Http/Middleware): the JWT out of `Authorization: Bearer`
src/Http/NullCredentialsExtractor.php  kept from 1.0: no credential minting through the framework middleware
src/Http/UnauthorizedResponder.php   kept from 1.0: every auth failure of the host's routes is a 401 envelope
src/Token/TokenFactoryBridge.php     the framework's TokenFactoryInterface over Graph::tokenFactory()
src/Token/DualToken.php              one token satisfying the framework's and the Polaris contract
src/Console/Commands.php             the six polaris/cli commands as polaris:*
migrations/20260910.000000_0_install_polaris.php
tests/Harness.php                    the functional suite through Relay (below)
```

## The module

`Module::apply(Container $container)` builds one `Polaris` from the environment and what the container already
binds, then binds the services. Every port takes the container's binding when present, else core's default:

- **Secrets and settings**: `Polaris\Config\EnvironmentConfig::secrets()` and `::auth()` read the same
  variables 1.0 read (`APP_KEY`, `AUTH_JWT_*`, `AUTH_ISSUER`, `AUTH_AUDIENCE`, `AUTH_ACCESS_TOKEN_DENYLIST`,
  `AUTH_PASSWORD_BREACH_CHECK`); a `Polaris\Config\Secrets` or `AuthConfig` instance bound before `apply()` wins.
  `univeros/configuration` has no configuration repository, only `Altair\Configuration\Support\Env`, so the
  environment is the configuration.
- **Database**: a bound `Polaris\Contract\DatabaseAdapter` or `PDO` first; otherwise a PDO opened from the
  framework's `Altair\Persistence\Configuration\DatabaseSettings` (`CycleOrmConfiguration` binds it shared from
  `DB_CONNECTION`, `DB_DATABASE`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`; drivers `postgres`, `mysql`,
  `sqlite`); otherwise `POLARIS_DSN` for an application without an ORM. Cycle's `Driver::getPDO()` is protected
  (`cycle/database` 2.23, `src/Driver/Driver.php`), so the handle cannot be shared: Polaris opens its own
  connection beside Cycle's, on the same settings. Wrap it in `Polaris\Pdo\PdoAdapter`
  (`PRAGMA foreign_keys = ON` on SQLite).
- **Cache, logger, dispatcher**: `Psr\SimpleCache\CacheInterface`, `Psr\Log\LoggerInterface` and
  `Psr\EventDispatcher\EventDispatcherInterface` when bound. The framework binds none of the three by default
  except the logger through `Altair\Logging\Configuration\LoggingConfiguration`; rate limits, the denylist and
  the OTP send caps live in the cache, so a production host binds `Altair\Cache\SimpleCache` (or any PSR-16) that
  outlives a request. Without a dispatcher the module binds a ten-line PSR-14 dispatcher of its own with
  `Polaris::listeners()` subscribed (the audit log, notifications, metrics); a host's own dispatcher is used as
  is, and the host subscribes `Polaris::listeners()` itself (documented).
- **Bindings**: `Polaris\Polaris`, `Polaris\Wiring\Graph`, `Polaris\Psr15\Pipeline` (built on
  `Laminas\Diactoros\ResponseFactory`, `pathPrefix` from `POLARIS_PATH_PREFIX`, a variable of this module since core
  names none, default `/`), `PolarisMiddleware`;
  `Altair\Http\Contracts\TokenFactoryInterface` to `TokenFactoryBridge`, `TokenExtractorInterface` to
  `BearerTokenExtractor`, `CredentialsExtractorInterface` to `NullCredentialsExtractor`, and a
  `TokenAuthenticationMiddleware` factory with `['ssl' => false, 'onError' => new UnauthorizedResponder()]`,
  as 1.0's `HttpBindings::bindMiddleware()` did. The application puts that middleware on its own routes
  (`MiddlewareProviderInterface` at `MiddlewarePriority::DISPATCHER + 5` with a `RequestPathRule` for its
  protected paths, exactly the 1.0 shape) and reads the token from
  `$request->getAttribute(Altair\Http\Contracts\TokenInterface::TOKEN_KEY)`.

`middleware()` returns `[['middleware' => PolarisMiddleware::class, 'priority' => MiddlewarePriority::EXCEPTION_HANDLER - 100]]`.
The skeleton's `public/index.php` (`composer create-project univeros/univeros`, framework 2.5.1) merges module
middleware through `Altair\Http\Support\ModuleMiddleware::collect()`, so nothing in the application changes:
the middleware runs first, outside `ExceptionHandlerMiddleware`, which is deliberate. That middleware rewrites
every response with a 4xx or 5xx status into problem+json (`Altair\Http\Middleware\ExceptionHandlerMiddleware::process()`),
and Polaris answers its own envelopes; the routes are therefore not registered through `RoutesProviderInterface`
either, since FastRoute would never dispatch them. `bin/altair polaris:manifest` lists them.

`PolarisMiddleware` (the version tried in `polaris-core` PR #17, which passed the shared walkthrough):

```php
final readonly class PolarisMiddleware implements MiddlewareInterface
{
    public function __construct(private Router $router, private Pipeline $pipeline) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $match = $this->router->match($request->getMethod(), $request->getUri()->getPath());
        if ($match->spec === null && $match->allowedMethods === []) {
            return $handler->handle($request);          // not a Polaris path: the framework's dispatcher
        }

        return $this->pipeline->handle(self::withJsonBody($request));   // a wrong method answers Polaris's 405
    }

    private static function withJsonBody(ServerRequestInterface $request): ServerRequestInterface
    {
        // ServerRequestFactory::fromGlobals() hands $_POST over as the parsed body: an empty array for JSON.
        $parsed = $request->getParsedBody();
        if (($parsed !== null && $parsed !== []) || !str_contains($request->getHeaderLine('Content-Type'), 'json')) {
            return $request;
        }
        $decoded = json_decode((string) $request->getBody(), true);

        return is_array($decoded) ? $request->withParsedBody($decoded) : $request;
    }
}
```

`Router` is `Polaris\Psr15\Router` built on `$polaris->manifest()` and the same prefix as the pipeline.

## The token bridge

The framework's `TokenAuthenticationMiddleware` stores the token it gets from `TokenFactoryInterface` on the
request under `TokenInterface::TOKEN_KEY`, and the Polaris services read `Polaris\Contract\TokenInterface`.
`DualToken` implements both (both declare `getToken(): string` and `getMetadata(?string $key = null): mixed`;
the Polaris contract carries no `TOKEN_KEY` constant so one class can implement the two). `TokenFactoryBridge`
implements `Altair\Http\Contracts\TokenFactoryInterface` over `Graph::tokenFactory()`: `fromTokenString()` and
`fromCredentials()` wrap the result in a `DualToken` and rethrow `Polaris\Exception\InvalidTokenException` as
`Altair\Http\Exception\InvalidTokenException` and `Polaris\Exception\AuthorizationTokenException` as
`Altair\Http\Exception\AuthorizationTokenException`, so the framework middleware keeps answering 401 and 403.
(`polaris-core`'s history has the two classes verbatim: `git show origin/extract/wp5:packages/core/src/Bootstrap/AltairTokenFactoryBridge.php`
and `DualToken.php`, written during the extraction.)

## Migrations

`migrationDirectories()` returns `[new MigrationSource(dirname(__DIR__) . '/migrations', 'Univeros\\Polaris\\Migrations')]`.
`Altair\Persistence\Migrations\ModuleMigrationDirectories` hands the directory to Cycle as a vendor directory,
and Cycle reads the class name from the file (`cycle/migrations` `FileRepository`: file names are
`Ymd.His_<chunk>_<name>.php`, the class is instantiated without arguments and `up()` runs inside a transaction on
Cycle's connection). The one migration:

```php
final class InstallPolaris extends \Cycle\Migrations\Migration
{
    protected const string DATABASE = 'default';

    public function up(): void
    {
        SchemaInstaller::create(self::pdo());     // the tables for the dialect, the permission catalog, the system roles
    }

    public function down(): void
    {
        SchemaInstaller::drop(self::pdo());
    }

    private static function pdo(): PDO         // the same DB_* settings CycleOrmConfiguration reads, or POLARIS_DSN
    {
        return Module::pdo(DatabaseSettings::fromEnv(Module::databaseEnvironment(new Env())));
    }
}
```

A second connection is what makes this work on a SQLite file and on PostgreSQL: Cycle's deferred `BEGIN` holds
no lock while `up()` runs, so the DDL and the seed commit on the module's connection before Cycle records the
migration on its own. A SQLite `:memory:` database cannot be shared between two connections; the tests use a
file or the in-memory `DatabaseAdapter`. `polaris schema:diff` on the same settings proves the result.

## Console

`Altair\Cli\Application` extends `Symfony\Component\Console\Application`, so the `polaris/cli` commands are
added as they are, renamed with `setName()`: `polaris:schema:export`, `polaris:schema:create`,
`polaris:schema:drop`, `polaris:schema:diff`, `polaris:manifest`, `polaris:doctor`. `SchemaCreateCommand`,
`SchemaDropCommand` and `SchemaDiffCommand` take a connection provider (`?callable` returning a `PDO`),
`DoctorCommand` takes the secrets, the auth settings and the connection; `Commands::all(Container $container)`
returns the six built on the module's bindings.

The framework's `vendor/bin/altair` boots a bare container with `CliConfiguration` only, so neither
`db:migrate` nor the module's commands can run from it; the framework's documentation
(`docs/packages/messaging.md`, "Host-application boot is required") expects the application to ship its own
`bin/altair`:

```php
$container = require dirname(__DIR__) . '/config/container.php';   // configurations, then the modules
(new CliConfiguration([/* the framework's built-in command directories, the app's */]))->apply($container);
$application = $container->make(Application::class);
foreach (Commands::all($container) as $command) {
    $application->add($command);
}
exit($application->run());
```

`univeros/cli` discovers `#[Command]` classes by scanning directories (`CommandLocatorInterface::scan()`); it
has no module hook, which is why the module exposes `Commands::all()` for the entry point.

## The proof: the functional suite and the 184 fixtures through Relay

`polaris/core` ships its `tests/` in the split repository (no `export-ignore`), and its functional suite takes a
harness class from `POLARIS_HARNESS` (`Polaris\Tests\Functional\Harness`: `create(Config)`, `graph()`,
`handle(ServerRequestInterface)`, `transportHeaders()`). `phpunit.xml.dist` declares the suite:

```xml
<testsuite name="functional">
    <directory>vendor/polaris/core/tests/Functional</directory>
    <directory>vendor/polaris/core/tests/Contract</directory>
</testsuite>
```

`Univeros\Polaris\Tests\Harness::create(Config $config)` builds an `Altair\Container\Container`, binds the
test's instances before the module runs (`DatabaseAdapter`, `OtpMailerInterface`, `SmsSenderInterface`,
`EventDispatcherInterface`, `Secrets`, `AuthConfig`, and `CacheInterface` as `Polaris\Support\InMemoryCache`),
then applies `new ModuleConfiguration([new Module()])`; `handle()` serialises a parsed body to JSON bytes with
an empty parsed body (what `ServerRequestFactory::fromGlobals()` produces) and runs the skeleton's pipeline,
`new Relay([PolarisMiddleware, ExceptionHandlerMiddleware, DispatcherMiddleware (an empty FastRoute table),
ActionMiddleware])`; `transportHeaders()` is `[]`, Relay adds nothing. Then:

```sh
POLARIS_HARNESS='Univeros\Polaris\Tests\Harness' vendor/bin/phpunit --testsuite functional
```

Expected: 184 fixtures, 1,201 steps, `ContractCoverageTest` asserting the 52 routes; `DB_CONNECTION` unset
runs on SQLite in memory, the `DB_*` variables of `CycleOrmConfiguration` select PostgreSQL in CI. The two
task-1 tests that failed once each under a load average above 18 and passed on rerun are
`UserAdminEndpointsTest::testPlainUserLacksPermissionToDisableOrEnable` and `LoginEndpointTest::testLockAutoExpires`.

## Demo

The `polaris-core` PR #17 branch (closed unmerged) held a Univeros host on the `univeros/univeros` skeleton:
`config/modules.php` registering the module, the skeleton's `public/index.php` unchanged, `bin/setup` (`.env`,
RS256 keys, the schema, `schema:diff`, `doctor`), a JSON-lines mailbox in `var/mail.log`, and
`examples/walkthrough.sh` from `polaris-core` (register, verify, login, TOTP, MFA login, organization,
switch-org). The same shape fits `examples/` of the `univeros/polaris` repository, with `bin/altair db:migrate`
in place of `schema:create` and a `/app/me` action behind the framework's `TokenAuthenticationMiddleware`.

## CHANGELOG

```markdown
## [2.0.0] - unreleased

`univeros/polaris` 2.0 is a new major built on Polaris for PHP: `polaris/core` carries the
identity, MFA/OTP, session, organization and RBAC services, the 52 endpoints and the
schema, all contract-frozen against 1.0 (184 recorded request/response sequences replay
through this module's Relay pipeline in CI); this package is the Univeros module around
it. The HTTP contract of 1.0 is unchanged (`docs/auth/api-reference.md` in polaris-core),
with one documented exception: a request body field named like a request attribute no
longer overrides the attribute.

### Changed
- The module builds Polaris from the environment (`APP_KEY`, `AUTH_JWT_*`, `AUTH_ISSUER`,
  `AUTH_AUDIENCE`) on the application's database settings (`DB_*`, or `POLARIS_DSN` without
  an ORM) through `polaris/pdo`; the framework's cache, logger and event dispatcher are used
  when bound.
- Routes: `PolarisMiddleware`, contributed through `MiddlewareProviderInterface` ahead of the
  framework's exception handler, serves every Polaris path; the routes are no longer in the
  FastRoute table (`bin/altair polaris:manifest` lists them).
- Migrations: one Cycle migration installs the schema and seeds the permission catalog through
  `Polaris\Pdo\SchemaInstaller`; the 18 migrations of 1.x are gone. `bin/altair db:migrate`
  on a fresh database installs Polaris.
- The framework's `TokenAuthenticationMiddleware` keeps working with Polaris access tokens
  through `TokenFactoryBridge`.
- Console: `polaris:schema:export`, `polaris:schema:create`, `polaris:schema:drop`,
  `polaris:schema:diff`, `polaris:manifest`, `polaris:doctor` from `polaris/cli`.

### Removed
- Every class under `Univeros\Polaris\` except the module glue; use the `Polaris\` namespaces
  of `polaris/core`. Cycle entities and repositories: Polaris no longer maps entities into the
  application's ORM schema.
- The AES-CBC encrypter of 1.x. There is no compatibility path (see UPGRADE).
```

## UPGRADE (1.x to 2.0)

```markdown
# Upgrading from 1.x to 2.0

2.0 is a breaking change. 1.x installations are not affected by this release and keep
working; upgrade when you can re-enrol MFA.

1. `composer require univeros/polaris:^2.0`. The `polaris/*` packages come with it.
2. Replace `Univeros\Polaris\*` imports with the `Polaris\*` classes of `polaris/core`
   (`Polaris\Model\User`, `Polaris\Event\*`, `Polaris\Contract\*`); the module itself stays
   `Univeros\Polaris\Module` in `config/modules.php`.
3. Database: 2.0 does not migrate 1.x tables. On a new database `bin/altair db:migrate`
   installs the 2.0 schema. On an existing one, export your users and organizations, install
   2.0, and import them; `bin/altair polaris:schema:diff` reports any difference between the
   database and the schema 2.0 expects.
4. TOTP secrets encrypted by 1.x cannot be read by 2.0: the encrypter changed (XChaCha20-Poly1305
   keyed by HKDF from `APP_KEY`) and no compatibility decrypter is provided. Users re-enrol their
   TOTP factors after the upgrade. Recovery codes are stored hashed under a key derived from
   `APP_KEY`; prove in a test that 1.x hashes verify under 2.0 before relying on it, otherwise
   users regenerate them after re-enrolling.
5. The Polaris routes are no longer in the FastRoute table: if your application listed or
   overrode them in `config/routes.php`, remove those entries. Your own routes keep using the
   framework's `TokenAuthenticationMiddleware`.
6. Subscribe `$polaris->listeners()` to your PSR-14 dispatcher if you bind one; without one the
   module dispatches Polaris events itself.
```
