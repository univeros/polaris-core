# polaris/core

The framework-free core of [Polaris for PHP](https://github.com/univeros/polaris-core):
self-hosted authentication, MFA/OTP, sessions with rotating refresh tokens, multi-tenant
organizations and RBAC, an audit log and PSR-14 events. Namespace `Polaris\`. It depends only
on PSR interfaces and a few libraries (`lcobucci/jwt`, `spomky-labs/otphp`, `endroid/qr-code`,
`symfony/uid`, `symfony/yaml`).

## Install

```sh
composer require polaris/core
```

You also need an HTTP adapter and a database adapter: `polaris/psr15` for any PSR-15 host and
`polaris/pdo` for PostgreSQL, MySQL or SQLite (`polaris/testing` has an in-memory adapter for
tests). `polaris/cli` adds `bin/polaris` for schema export and diff, the manifest and `doctor`.

## Use

```php
use Polaris\Config\EnvironmentConfig;
use Polaris\Polaris;
use Polaris\Wiring\Config;

$polaris = Polaris::create(new Config(
    secrets: EnvironmentConfig::secrets(),   // APP_KEY, AUTH_JWT_* from the environment
    auth: EnvironmentConfig::auth(),         // issuer, audience, feature flags
    database: $adapter,                      // Polaris\Contract\DatabaseAdapter
    mailer: $mailer,                         // OtpMailerInterface: verification, reset and OTP emails
    sms: $sms,                               // SmsSenderInterface
    dispatcher: $dispatcher,                 // PSR-14; subscribe $polaris->listeners()
));

$polaris->graph()->login();   // every service, built once, no container
$polaris->manifest();         // the 52 endpoints declared in api/**/*.yaml
$polaris->schema();           // the tables, as data
```

Every port has a working default (in-memory cache, log mailer and SMS sender, system clock,
libsodium encrypter, PSR-3 metrics); pass your own to replace it.

## What is in the package

| Directory | Contents |
| --- | --- |
| `api/` | The HTTP contract: one YAML spec per endpoint, loaded at runtime as the router |
| `src/Contract` | The ports: database adapter, repositories, tokens, encrypter, mailer, SMS, rate store, metrics |
| `src/Identity`, `src/Mfa`, `src/Token`, `src/Authorization` | The domain services |
| `src/Http` | `Input`, `Result`, the `Endpoint` base, the endpoints, the manifest loader |
| `src/Schema`, `src/Model`, `src/Repository` | The schema as data, the plain models, the repositories over any `DatabaseAdapter` |
| `src/Wiring` | `Config` and `Graph`: the object graph, built explicitly |

## Documentation

The specification (flows, data model, MFA, RBAC, security, the API reference) lives in the
monorepo under [`docs/auth/`](https://github.com/univeros/polaris-core/tree/main/docs/auth);
the Slim demo under
[`examples/slim/`](https://github.com/univeros/polaris-core/tree/main/examples/slim) is the
smallest complete host.

## License

MIT.
