# Polaris for PHP

> **Self-hosted authentication, MFA, organizations and RBAC for any PHP application.**
> Framework-free core, PSR-15 for HTTP, PDO for storage, one object graph and no container.

![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?logo=php&logoColor=white)
![Framework-agnostic](https://img.shields.io/badge/framework-agnostic-1d76db)
![Multi-tenant](https://img.shields.io/badge/multi--tenant-RBAC-0052cc)
![MFA](https://img.shields.io/badge/MFA-TOTP%20%C2%B7%20SMS%20%C2%B7%20email-d93f0b)
![License](https://img.shields.io/badge/license-MIT-green)

Polaris gives an application a complete identity stack it owns: email-verified
registration, password login with Argon2id, JWT access tokens with **rotating
refresh tokens** and theft detection, **multi-factor authentication** (TOTP by QR,
SMS, email, recovery codes, step-up), **multi-tenant organizations with role-based
access control**, an append-only audit log and PSR-14 events. The HTTP contract is
52 endpoints declared in `packages/core/api/**/*.yaml`; every response is contract-frozen by a
recorded fixture suite.

The name is the idea: *Polaris* is the fixed star your application's identity
navigates by.

---

## Packages

| Package | Namespace | What it is |
| --- | --- | --- |
| `polaris/core` | `Polaris\` | The domain: identity, MFA, tokens, organizations, authorization, the schema, the endpoints, the manifest, the wiring. Depends only on PSR interfaces and a few libraries (`lcobucci/jwt`, `spomky-labs/otphp`, `endroid/qr-code`, `symfony/uid`, `symfony/yaml`). |
| `polaris/psr15` | `Polaris\Psr15\` | Router, middleware stack and request handler for any PSR-15 host (Slim, Mezzio, Laravel or Symfony through their PSR bridges). |
| `polaris/pdo` | `Polaris\Pdo\` | The database adapter for PostgreSQL, MySQL and SQLite, the DDL exporter and the schema inspector. |
| `polaris/testing` | `Polaris\Testing\` | The in-memory database adapter for tests of applications built on Polaris. |
| `polaris/cli` | `Polaris\Cli\` | `bin/polaris`: `schema:export`, `schema:diff`, `manifest` (JSON, OpenAPI 3.1), `doctor`. |
| `polaris/laravel` | `Polaris\Laravel\` | Laravel 13: service provider, the endpoints as routes, the `polaris` guard, mail bridge, `polaris:*` artisan commands. |
| `polaris/symfony` | `Polaris\Symfony\` | Symfony 7.4 / 8: bundle, the endpoints as routes, a firewall authenticator, mail bridge, `polaris:*` console commands. |
| `polaris/yii` | `Polaris\Yii\` | Yii 3: config plugin, the endpoints as routes, an authentication method, mail bridge, `polaris:*` console commands. |
| `@polaris-auth/client` (npm) | `packages/client-ts` | The TypeScript client generated from the manifest: `openapi-fetch` typed by the 52 endpoints, request bodies, `data` and `error` checked at compile time. |

This repository is the monorepo; each package is published to its own read-only
repository for Composer.

---

## Quick start

The fastest way to see everything is the Slim demo:

```sh
cd examples/slim
composer install
bin/setup            # .env, RS256 keys, SQLite schema, permission catalog
bin/walkthrough.sh   # register → verify → login → TOTP → MFA login → organization
```

The whole integration is [`examples/slim/src/bootstrap.php`](examples/slim/src/bootstrap.php):

```php
$polaris = Polaris::create(new Config(
    secrets: EnvironmentConfig::secrets(),   // APP_KEY, AUTH_JWT_* from the environment
    auth: EnvironmentConfig::auth(),         // issuer, audience, feature flags
    database: new PdoAdapter($pdo),          // PostgreSQL, MySQL or SQLite
    mailer: $mailer,                         // OtpMailerInterface: verification and OTP emails
    sms: $sms,                               // SmsSenderInterface
    dispatcher: $dispatcher,                 // PSR-14; subscribe $polaris->listeners()
));

$pipeline = new Pipeline($polaris->graph(), $responseFactory);
$pipeline->middleware();   // ordered PSR-15 middleware for your stack
$pipeline->handler();      // the PSR-15 handler serving every route in packages/core/api/
```

Every port has a working default (in-memory cache, log mailer and SMS sender, system
clock, libsodium encrypter, PSR-3 metrics); pass your own to replace it.

In Laravel the same graph comes from `config/polaris.php` and Laravel's own services:

```sh
composer require polaris/laravel
php artisan polaris:install && php artisan migrate   # config, tables, permission catalog
```

then `Route::middleware('auth:polaris')` protects your routes with Polaris access tokens
([`examples/laravel`](examples/laravel) is the complete host).

In Symfony, register `Polaris\Symfony\PolarisBundle`, describe the same graph under `polaris:`
in `config/packages/polaris.yaml`, import the routes with `type: polaris`, and put
`Polaris\Symfony\Security\PolarisAuthenticator` on a firewall
([`examples/symfony`](examples/symfony) is the complete host).

In Yii 3, `polaris/yii` is a `yiisoft/config` plugin: set the `polaris` params, and the routes,
the definitions, the `polaris/authentication` middleware and the `polaris:*` commands are there
([`examples/yii`](examples/yii) is the complete host).

From a browser or Node, `@polaris-auth/client` ([`packages/client-ts`](packages/client-ts)) is the same
contract typed: `createClient({ baseUrl, token })` over `openapi-fetch`, generated from
`polaris manifest --format=openapi` and drift-checked in CI.

---

## Features

| Area | What you get |
| --- | --- |
| **Authentication** | Register, email verification, password login, `/auth/me`, logout / logout-all |
| **Tokens** | Asymmetric JWT access tokens (RS256/EdDSA) + opaque **rotating refresh tokens** with reuse detection; JWKS endpoint |
| **Sessions** | Per-device session list, individual + global revocation |
| **MFA / OTP** | **TOTP (QR)**, **SMS OTP**, **email OTP**, recovery codes, login-MFA gate, step-up |
| **Passwords** | Argon2id, policy enforcement, breached-password hook, reset & change (logout-everywhere) |
| **Multi-tenant RBAC** | Organizations, memberships, roles, permissions, invitations, org switching |
| **Authorization** | Declarative per-endpoint permissions + a programmatic `Gate` |
| **Security** | Rate limiting, account lockout, anti-enumeration, audit log, key rotation |
| **Ops** | PSR-14 domain events, notification fan-out, transient-row pruning, metrics |

---

## How it works

```
HTTP        core/api/**/*.yaml   the manifest: method, path, auth, rate limit, effect, input rules, endpoint class
            Polaris\Psr15        RouteMiddleware → ClientContext → rate limits → token / MFA-ticket auth → step-up → denylist → authorization → RequestHandler
            Polaris\Http         Endpoint(Input): Result — parse, call a service, map the outcome
Domain      Identity, Mfa, Token, Authorization   services, transactional, emitting PSR-14 events
            Polaris\Contract     ports: DatabaseAdapter, repositories, tokens, encrypter, mailer, SMS, rate store, metrics, …
Persistence Polaris\Schema       the tables as data; Polaris\Repository over any DatabaseAdapter (polaris/pdo, polaris/testing)
Wiring      Polaris\Wiring\Graph every service built explicitly from a Config; no container
```

Login returns a short-lived **JWT access token** plus a **rotating refresh
token**; presenting an already-rotated refresh token is treated as theft and
revokes the entire token family.

---

## API surface

A representative slice (full catalog in
[`docs/auth/api-reference.md`](docs/auth/api-reference.md); `bin/polaris manifest --format=openapi`
renders the OpenAPI 3.1 document):

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/register` | Create account, send verification |
| `POST` | `/auth/login` | Password login → tokens **or** MFA challenge |
| `POST` | `/auth/token/refresh` | Rotate refresh → new access + refresh |
| `POST` | `/auth/mfa/totp/enroll` | Start TOTP enrollment → secret + QR |
| `POST` | `/auth/mfa/verify` | Complete MFA → tokens |
| `GET`  | `/auth/sessions` | List active devices/sessions |
| `POST` | `/orgs` | Create an organization (creator → owner) |
| `POST` | `/orgs/{id}/invites` | Invite a member |
| `POST` | `/auth/switch-org` | Switch active org → re-scoped token |

Routes are relative; mount the handler under whatever prefix your application uses
(`Pipeline` takes a path prefix).

---

## Multi-factor authentication

Three factor types, one uniform verification flow:

- **TOTP (authenticator app)** — RFC 6238 via `spomky-labs/otphp`; enrolled by
  scanning a QR code (`otpauth://` provisioning URI). Secrets are encrypted at
  rest (XChaCha20-Poly1305).
- **SMS OTP** — 6-digit codes delivered through your `SmsSenderInterface`.
- **Email OTP** — 6-digit codes delivered through your `OtpMailerInterface`.
- **Recovery codes** — 10 single-use codes, hashed at rest.
- **Step-up** — sensitive operations (password change, removing a factor, deleting
  an org or a user) require a recent strong authentication.

Details in [`docs/auth/mfa-otp.md`](docs/auth/mfa-otp.md).

---

## Multi-tenant RBAC

Identity is global; authority is scoped to an organization:

```
User ──< Membership >── Organization
              └──< roles >── permissions   (per-org; system roles when org is null)
```

Org creators become `owner`; `admin`/`member` templates are seeded per org and
fully customizable. The access token carries the active org and resolved roles, so
authorization is mostly stateless; the authorization middleware enforces
per-endpoint permissions and a `Gate` handles the rules permissions can't express
(last-owner protection, role hierarchy). Cross-tenant access is denied by design.
See [`docs/auth/rbac.md`](docs/auth/rbac.md).

---

## Security

Polaris follows established standards — **JWT** (RFC 7519), **JWKS** (RFC 7517),
**TOTP** (RFC 6238), **OAuth 2.0 refresh semantics + Security BCP** (RFC 9700), and
**OWASP ASVS** for password storage. Secrets are never stored in plaintext (hashed
or encrypted at rest), comparisons are constant-time, and signing keys are
asymmetric with `kid`-based rotation. Full threat model in
[`docs/auth/security.md`](docs/auth/security.md).

---

## Database

The schema is data (`Polaris\Schema`), so there are no migrations to carry:

```sh
bin/polaris schema:export --target=sql:postgres > schema.sql   # also sql:mysql, sql:sqlite
bin/polaris schema:diff --dsn='pgsql:host=…;dbname=…'           # what a live database is missing
bin/polaris doctor --dsn=…                                       # secrets, keys, manifest, connectivity, schema
```

`polaris/pdo` runs on PostgreSQL, MySQL and SQLite; the adapter conformance suite
runs on all of them plus the in-memory adapter.

---

## Documentation

The specification lives in [`docs/auth/`](docs/auth/):

| Doc | Contents |
| --- | --- |
| [README](docs/auth/README.md) | Overview and goals |
| [data-model](docs/auth/data-model.md) | Models, tables, relationships |
| [flows](docs/auth/flows.md) | Register, login, refresh rotation, sessions, password |
| [mfa-otp](docs/auth/mfa-otp.md) | TOTP/QR, SMS, email, recovery, step-up |
| [rbac](docs/auth/rbac.md) | Orgs, memberships, roles, permissions, guard |
| [api-reference](docs/auth/api-reference.md) | Full endpoint catalog + error format |
| [security](docs/auth/security.md) | Threat model, crypto, key management |
| [configuration](docs/auth/configuration.md) | Config schema, env, deps |
| [events](docs/auth/events.md) | PSR-14 domain events |
| [testing](docs/auth/testing.md) | Test strategy + acceptance criteria |

The extraction from the Univeros module, with every decision taken, is in
[`docs/extraction/`](docs/extraction/). Agent-oriented orientation is in
[`AGENT.md`](AGENT.md).

---

## Testing

```sh
composer install
composer qa          # phpcs, phpstan, forbidden-import check, phpunit
```

Without `DB_CONNECTION` the database tests run on in-memory SQLite (the whole suite
in about a minute); CI runs them against PostgreSQL. The functional suite replays
184 recorded 1.0 fixtures through the PSR-15 pipeline, so every response is
contract-frozen.

---

## Contributing

Issues and pull requests are welcome on
[github.com/univeros/polaris-core](https://github.com/univeros/polaris-core). Please
read [`AGENT.md`](AGENT.md) first, follow the conventions (strict types,
immutability, small files, tests-first), and run `composer qa` before opening a PR.

---

## License

MIT, see [`LICENSE`](LICENSE). Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
