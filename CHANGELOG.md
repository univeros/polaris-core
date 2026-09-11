# Changelog

All notable changes to Polaris for PHP (the `polaris/*` packages) are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`polaris/sso`** (`Polaris\Sso\`): per-organization SAML 2.0 (onelogin/php-saml, strict: signatures,
  one assertion, audience, destination, drift, `InResponseTo`, replay) and OpenID Connect (discovery, PKCE,
  nonce, the id_token against the JWKS through firebase/php-jwt) providers; verified domains (a DNS TXT
  record or a well-known file) route an email to its provider; just-in-time users and memberships with the
  provider's default roles; the sign-in ends on the application's `redirect_uri` with a one-time code that
  `POST /sso/exchange` turns into the login envelope, the session scoped to the organization (`amr: sso`);
  single logout both ways (signed IdP logout requests, `POST /sso/logout` for the application); the SP
  metadata; the organization's self-service routes under `/orgs/{id}/sso` (`org.update`), the operators'
  under `/admin/sso`; every action and rejection an `sso.*` audit event.
- `@polaris-auth/client`: `client.sso.*`.

### Changed
- `Result::$raw`: an endpoint may answer a body as is with its own Content-Type (the SAML metadata XML);
  the JSON responder writes it unchanged.
- The OpenAPI document types a nullable field (`?integer`, `?boolean`, `?list<string>`) as its type and an
  `object` field as an object, so the generated client checks the bodies of the plugin routes; core's
  `permission_keys` is typed as an array now.

## [0.4.0] - 2026-09-11

`polaris/sentinel`, the risk engine in front of the guarded auth routes.

### Added
- **`polaris/sentinel`** (`Polaris\Sentinel\`): a local risk engine on sign-up, sign-in, password reset and
  code sends, as PSR-15 middleware in front of the guarded routes: velocity, credential stuffing, IP rules,
  devices and disposable domains out of the box, captcha (Turnstile, hCaptcha), impossible travel (MaxMind
  DB) and breached passwords (HIBP) with a provider; a policy that allows, challenges or blocks (sum capped
  at 100; allow below 40, challenge from 40, block from 80; a verified captcha token turns a challenge into
  an allow); `observe` records without enforcing, `enforce` answers `sentinel/blocked` and, with a captcha
  verifier, `sentinel/challenge_required` (`challenge: captcha`, the client retries with `captcha_token`);
  every decision where a signal spoke is a row in `polaris_sentinel_decision` and a `sentinel.evaluated`
  audit event; the `polaris_device` cookie; `GET /admin/sentinel/decisions`, `GET|POST /admin/sentinel/ip-rules`,
  `DELETE /admin/sentinel/ip-rules/{id}` and `POST /admin/sentinel/unblock` for the admin plugin's
  principals; `sentinel:lists`; the bundled disposable-domain list (CC0). The breach checker also serves
  core's password-policy port; `polaris/messaging` takes its quiet mode.
- `@polaris-auth/client`: `client.sentinel.*`.

### Changed
- `Graph::port()` is public: a package takes another package's optional contribution the way the graph
  takes a plugin-provided port (`polaris/messaging` takes a `Suppressor` from the graph when the host passes
  none).
- The packages' version line is 0.4: `^0.4` between siblings, `0.4.x-dev` on the path repository and
  in the demos.

## [0.3.0] - 2026-09-11

`polaris/messaging`, the client namespaces for the plugins, and the port rule that lets a plugin serve
core.

### Changed
- The packages' version line is 0.3: `^0.3` between siblings, `0.3.x-dev` on the path repository and
  in the demos (a package at 0.3.0 requires its siblings at 0.3.0).

### Added
- `@polaris-auth/client`: the plugins' routes as namespaces, `client.audit.*` and `client.admin.*`, one
  typed method per endpoint, generated from the OpenAPI document (`x-polaris-plugin`); `ProblemBody`
  types their RFC 9457 errors. The OpenAPI document marks a plugin's operations, answers their errors as
  `application/problem+json` (`Problem` schema), keeps operation ids unique across plugins and types
  `list<x>` fields as arrays. `EndpointSpec::$plugin` names the plugin a route belongs to.
- The Slim demo registers the audit and admin plugins; `bin/setup` writes an owner API key to
  `var/admin.key`, which the client's smoke test uses.
- **`polaris/messaging`** (`Polaris\Messaging\`): templated, translated (en, es, de, fr, pt), rate-limited
  email and SMS through pluggable channels (Symfony Mailer, PHPMailer, Twilio, Vonage, log, array), with
  instance and per-organization template overrides (`polaris_messaging_template`), a fallback kind, quiet
  mode through a `Suppressor`, an `Outbox` queue seam, `messaging:send`; it becomes core's mailer and SMS
  sender when the configuration leaves them unset, and every delivery is `messaging.sent` in the audit store.
- A plugin may provide a core port (the mailer, the SMS sender, the breach check, the metrics) through
  `services()` keyed by the contract; the graph takes it when the configuration leaves the port unset.

## [0.2.0] - 2026-09-11

The plugin runtime and the first two packages on it: `polaris/audit` and `polaris/admin`. One version
line for every package.

### Added
- The plugin runtime: `Polaris\Contract\Plugin` and `Polaris\Plugin\AbstractPlugin`, `Config::$plugins`;
  a plugin's models join the schema (export, create, diff, install), its `api/<id>/**/*.yaml` specs
  join the manifest and the router, its services resolve endpoint constructors, its listeners join
  `Polaris::listeners()`, its permissions the catalog; `Polaris::plugin()`, `Graph::get()`.
  `Endpoint::problem()` answers RFC 9457 problem documents (`application/problem+json`) for plugin
  routes. The CLI commands take `--bootstrap` (`POLARIS_BOOTSTRAP`) to see an application's plugins;
  the adapters take `plugins` in their configuration. `docs/plugins/README.md` documents the contract.
- Contract fixtures can be recorded (`POLARIS_RECORD_FIXTURES=1`) into a package's own directory, so
  a plugin proves its routes through every harness like core.
- **`polaris/audit`** (`Polaris\Audit\`): a catalogued, redacted, append-only audit store built on the
  plugin runtime: core's events recorded with actor, subject, organization and client context; `GET
  /audit/me`, `/audit/organization/{id}` (with `audit.read`) and `/audit/types`, cursor-paginated;
  sinks (database, PSR-3, JSON lines, signed webhooks) and per-organization drains; retention by
  policy (`audit:prune`), an optional hash chain (`audit:verify`); `last_active_at` per user.
- `polaris/cli`: `Polaris\Cli\CommandProvider`; `bin/polaris` adds a plugin's commands when
  `POLARIS_BOOTSTRAP` names the application.
- **`polaris/admin`** (`Polaris\Admin\`): the operator API under `/admin` for admin users (a grant, or the
  superadmin role) and API keys (`pak_...`, hashed, with IP allowlist and expiry), with the
  viewer/support/admin/owner role matrix and instance or organization scopes: users (list, read, ban,
  unban, set password, delete, impersonate), sessions, MFA factors (remove, reset), organizations (list,
  read with members, member roles, delete), the instance-wide audit trail and the organizations' drains,
  statistics, keys and grants; `admin:key` and `admin:grant`; every action recorded as `admin.*` through
  `polaris/audit`.
- `Polaris\Contract\Plugin::middleware(Graph)`: PSR-15 middleware a plugin adds to the pipeline, right
  after the bearer token is parsed. `AccessTokenClaims::$extra` and `TokenService::mint()` mint an access
  token with a package's claims and no session; `UserAdminService::anonymize()` is the erasure without
  the self-or-permission check, for an operator whose authority is established.

## [0.1.1] - 2026-09-11

### Added
- A `LICENSE` file (MIT, copyright 2am.tech) in every package and at the root; `authors`
  (2am.tech) in every `composer.json` and in the client's `package.json`; every README ends
  with the 2am.tech attribution.

### Removed
- Six local artefacts of an earlier demo run committed by mistake under `examples/univeros`
  (a demo key pair, `.env`, the mailbox, a SQLite file, a server log); they carried no real
  secret and remain only in the history of `v0.1.0`.

## [0.1.0] - 2026-09-10

The first release of Polaris for PHP: the framework-agnostic packages extracted from
`univeros/polaris` 1.0.0 with every response contract-frozen, the Laravel, Symfony and Yii
adapters, and the TypeScript client. One version line for all of them.

### Framework adapters

- **`polaris/laravel`** (`Polaris\Laravel\`): a service provider that builds Polaris from
  `config/polaris.php` on Laravel's connection, cache, logger, events and mailer; the 52
  endpoints as named Laravel routes under `path_prefix`; the `polaris` guard
  (`auth:polaris`) for the application's own routes; `polaris:install` (config and the
  migration that creates the tables and seeds the catalog) and the CLI commands as
  `polaris:schema:export`, `polaris:schema:diff`, `polaris:manifest`, `polaris:doctor`; a
  plain-text mail bridge (`mailer: mail`). The functional suite and the 184 contract
  fixtures replay through Laravel's HTTP kernel in CI; `examples/laravel` runs the shared
  walkthrough. Spec and decisions in `docs/adapters/`.
- **`polaris/symfony`** (`Polaris\Symfony\`): a bundle whose `polaris:` configuration
  becomes the `Polaris`, `Graph` and `Pipeline` services on the application's connection
  (a DSN, a PDO, a Doctrine DBAL connection), cache, logger, dispatcher and mailer; the
  `polaris` route loader mounts the 52 endpoints as named routes; the authenticator
  (`custom_authenticators`) guards the application's firewalls with Polaris access
  tokens; `polaris:schema:create`, `polaris:schema:drop` and the CLI commands as
  `polaris:*`; a plain-text Symfony Mailer bridge (`mailer: mail`). The functional
  suite and the 184 contract fixtures replay through Symfony's HTTP kernel in CI;
  `examples/symfony` runs the shared walkthrough.
- **`polaris/yii`** (`Polaris\Yii\`): a `yiisoft/config` plugin whose `polaris` params
  become the `Config`, `Polaris`, `Graph` and `Pipeline` definitions on the application's
  connection (a DSN, a PDO or a `Yiisoft\Db` connection), cache, logger, dispatcher and
  mailer; the 52 endpoints as routes in the `routes` group, PSR-15 straight through; an
  authentication method and the `polaris/authentication` middleware for the application's
  own routes; the `polaris:*` commands for `yiisoft/yii-console`; a plain-text Yii mailer
  bridge (`mailer: mail`). The functional suite and the 184 contract fixtures replay
  through the Yii application in CI; `examples/yii` runs the shared walkthrough.
- `polaris/pdo`: `SchemaInstaller` creates the tables and seeds the catalog on a
  connection, or drops them; the adapters' migrations and commands call it.
- `polaris/cli`: `schema:create` and `schema:drop` (`--dsn`, or a host's connection).
- `polaris/core`: `Polaris\Notification\MailTemplates`, the plain-text subjects and
  bodies the Symfony and Yii mail bridges send.
- `polaris/cli`: `schema:diff` and `doctor` accept a host's connection, secrets and auth
  settings; `symfony/*` constraints allow Symfony 8.

### TypeScript client

- **`@polaris-auth/client`** (`packages/client-ts`, npm): `createClient({ baseUrl, token })`
  over `openapi-fetch`, typed by `src/schema.d.ts`, which `openapi-typescript` generates
  from `polaris manifest --format=openapi`; `withToken()` binds another token. Checked in
  and drift-checked in CI; the smoke test runs register, verify, login and `/auth/me`
  through the client against the Slim demo.
- `polaris manifest --format=openapi` types every success response from the spec's
  `output.example` (`Polaris\Http\Manifest\ExampleSchema`, JSON Schema by example;
  `example_<variant>` keys become a `oneOf`), so the generated client types `data`.

### Polaris for PHP: the framework-agnostic extraction

The 1.0 Univeros module became a monorepo of framework-free packages with the
same behaviour: `polaris/core` (`Polaris\`), `polaris/psr15`, `polaris/pdo`,
`polaris/testing`, `polaris/cli`. Every 1.0 response is contract-frozen: the
functional suite replays 184 request/response sequences (1,201 steps) recorded
from the 1.0 code through the PSR-15 pipeline. The extraction is documented in
`docs/extraction/` (spec, decisions, the one behaviour change).

- **Wiring.** `Polaris::create(new Polaris\Wiring\Config(...))` builds the
  service graph without a container; `Polaris\Psr15\Pipeline` gives any PSR-15
  host the ordered middleware and the request handler.
- **Persistence.** Models are plain records; the schema is data
  (`Polaris\Schema`); repositories run on a `DatabaseAdapter` (`polaris/pdo` for
  PostgreSQL, MySQL and SQLite; an in-memory adapter in `polaris/testing`). The
  18 Cycle migrations are replaced by `polaris schema:export`.
- **Routing.** `packages/core/api/**/*.yaml`, shipped inside `polaris/core`, is
  the router: 52 endpoints, each with `effect` and `receipt`, loaded by
  `Polaris\Http\Manifest`; the CLI renders OpenAPI 3.1.
- **Ports.** Repository, unit of work, tokens, identity provider, encrypter
  (`SodiumEncrypter` default, XChaCha20-Poly1305), rate store (PSR-16 default),
  metrics (PSR-3 default); PSR-14 listeners exposed through `Polaris::listeners()`.
- **CLI.** `bin/polaris schema:export`, `schema:diff`, `manifest`, `doctor`.
- **Demo.** `examples/slim`: Slim 4 on SQLite with an executable walkthrough.
- **Behaviour change (documented).** A request body field named like a request
  attribute no longer overrides the attribute (`docs/extraction/behaviour-changes.md`).

## [1.0.0] - 2026-06-11

First stable release: the authentication, MFA/OTP, and multi-tenant RBAC
module for the univeros framework. A host registers one `Module` class and
gets the full surface below as routes, entities, migrations, middleware, and
PSR-14 events. See `docs/auth/` for the specification and
`docs/auth/api-reference.md` for the implemented HTTP contracts (52
endpoints).

### Identity and sessions

- Registration with email verification (single-use hashed tokens,
  enumeration-safe responses) and resend.
- Password login with Argon2id hashing, transparent rehash, timing-equalized
  verification, sliding-window lockout, and optional verified-email and
  HIBP breach-check (k-anonymity) gates.
- JWT access tokens (RSA, JWKS endpoint, key-rotation overlap window) plus
  opaque rotating refresh tokens with family-based reuse detection: replaying
  a rotated token revokes the whole session family.
- Session management: device list, logout, logout-all, per-session revocation,
  and an optional instant access-token denylist.
- Password forgot/reset/change with logout-everywhere semantics; reset and
  verification tokens are stored only as keyed HMACs.

### MFA

- TOTP (RFC 6238, encrypted secrets, QR provisioning), SMS, and email factors
  with enrollment + confirmation flows; ten single-use recovery codes issued
  on the first confirmed factor.
- The login MFA gate: a short-lived single-purpose ticket bridges the password
  step to factor verification before any session is minted.
- Step-up re-authentication for sensitive operations, stamped via `auth_time`;
  `mfa`/`amr`/`auth_time` persist across refresh and org switching.
- OTP hygiene: codes stored as keyed HMACs, attempt budgets and consumption
  enforced by atomic conditional updates, send quotas and resend cooldowns
  against OTP bombing.

### Multi-tenant RBAC

- Organizations with soft delete, slug uniqueness, and per-org role templates
  (owner / admin / member) cloned from system templates; a global `superadmin`
  override for platform operators.
- Members: listing (with PII gating of invited/suspended emails), role
  assignment, suspension with immediate org-scoped session revocation, and
  removal.
- Single-use, expiring invitations bound to the invitee's email.
- Custom roles with a 12-key permission catalog; database-resolved
  authorization on every check (token claims are never trusted for authority).
- Tenant invariants enforced beyond the permission check: no privilege
  escalation, owners protected from non-owners, last-owner protection,
  cross-tenant isolation on every org route.
- User administration: read/update (self or admin), disable/enable, and
  anonymizing tombstone deletion.

### Hardening and operations

- Per-IP rate-limit budgets per endpoint group plus a global per-user budget
  across authenticated endpoints; user-agent sanitization at the edge.
- Two security audits (#44 sign-off and the #97 follow-ups) fully remediated:
  atomic rotation/OTP/recovery claims, APP_KEY minimum length, full-length
  key fingerprints, typed challenge purposes, abuse caps.
- Append-only audit log (actor, org, ip, user agent, whitelisted metadata),
  domain metrics counter, and notification listeners over a catalog of ~35
  PSR-14 events.
- 18 driver-portable migrations, scheduled pruning of expired transient rows,
  and a key-rotation runbook.
- Verified by 519 tests (unit, persistence against a real driver, and
  end-to-end functional tests over the real middleware pipeline), with phpcs
  (PSR-12) and phpstan level 5 clean.

### Documentation and agent experience

- Full specification under `docs/auth/` with the API reference and event
  catalog regenerated from the shipped code.
- One YAML spec per implemented endpoint under `api/`, verified 1:1 against
  the route table.
- An agent skill at `.ai/skills/polaris/SKILL.md` covering registration,
  configuration, the token model, the permission catalog, and the tenant
  invariants.

[Unreleased]: https://github.com/univeros/polaris-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/univeros/polaris-core/releases/tag/v0.1.1
[0.1.0]: https://github.com/univeros/polaris-core/releases/tag/v0.1.0
[1.0.0]: https://github.com/univeros/polaris/releases/tag/v1.0.0
