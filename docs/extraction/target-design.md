# Polaris for PHP — design v0.1

**One line.** Framework-agnostic, plugin-based authentication and authorization for PHP 8.3+, that runs in your app against your database, works identically in Laravel, Symfony, Yii, Slim, Mezzio and Univeros — and is the first auth library built for agents as principals.

**Reference point.** Better Auth (TS). We match its shape (core + adapters + plugins + typed client) and beat it on six things listed at the end.

---

## 1. Package layout

Composer vendor: `polaris/` (confirmed available on Packagist, September 2026). One monorepo, split-published.

| Package | Purpose | License |
|---|---|---|
| `polaris/core` | Users, accounts, sessions, verification, hashing, CSRF, rate limiting, plugin runtime, route manifest | MIT |
| `polaris/pdo` | Database adapter, plain PDO (Postgres, MySQL, SQLite) | MIT |
| `polaris/doctrine` | Doctrine DBAL adapter | MIT |
| `polaris/eloquent` | Eloquent/Illuminate DB adapter | MIT |
| `polaris/psr15` | PSR-15 handler + middleware (Slim, Mezzio, Univeros, anything PSR) | MIT |
| `polaris/laravel` | Service provider, guard, route registration, migration export | MIT |
| `polaris/symfony` | Bundle, authenticator, firewall integration | MIT |
| `polaris/yii` | Yii3 extension | MIT |
| `polaris/plugin-social` | OAuth providers (GitHub, Google, Microsoft, Apple, …) | MIT |
| `polaris/plugin-passkey` | WebAuthn registration and login | MIT |
| `polaris/plugin-totp` | TOTP + backup codes | MIT |
| `polaris/plugin-organizations` | Orgs, teams, invitations, roles | MIT |
| `polaris/plugin-magic-link` | Passwordless email | MIT |
| `polaris/client-js` (npm `@polaris-auth/client`) | Typed browser/Node client generated from the route manifest | MIT |
| `polaris/cli` | `polaris init / doctor / schema:diff / schema:export / manifest` | MIT |
| `polaris/testing` | In-memory adapters, fake mailer, time control, request helpers | MIT |
| `polaris/plugin-sso` | SAML / enterprise OIDC connections | Commercial (source-available) |
| `polaris/plugin-scim` | SCIM 2.0 provisioning | Commercial |
| `polaris/plugin-admin` | Admin dashboard (headless API + optional UI) | Commercial |
| `polaris/plugin-audit` | Audit log with SIEM export | Commercial |
| `polaris/plugin-agents` | Agent principals, delegation, budgets, approvals, receipts, earned autonomy | Commercial (free inside Univeros/Vela) |

Core has **zero framework dependencies**. Allowed: `psr/http-message`, `psr/http-server-middleware`, `psr/event-dispatcher`, `psr/simple-cache`, `psr/clock`, `psr/log`. Nothing else.

---

## 2. Developer experience

```php
use Polaris\Polaris;
use Polaris\Pdo\PdoAdapter;
use Polaris\Plugin\{EmailPassword, Social, Totp, Organizations, Passkey};

$auth = Polaris::create(
    database: new PdoAdapter($pdo),
    mailer:   new SymfonyMailerAdapter($mailer),   // or any Mailer implementation
    secret:   $_ENV['POLARIS_SECRET'],
    baseUrl:  'https://app.example.com',
    plugins: [
        new EmailPassword(requireVerification: true),
        new Social(github: ['id' => '…', 'secret' => '…']),
        new Passkey(rpName: 'Acme'),
        new Totp(issuer: 'Acme'),
        new Organizations(allowUserCreate: true),
    ],
);
```

Mount (PSR-15):

```php
$app->any('/auth/{path:.*}', $auth->handler());   // all auth endpoints
$app->add($auth->middleware());                    // resolves session into request attribute
```

Use:

```php
$session = $request->getAttribute(\Polaris\Session::class);   // null when anonymous
$session->user->id;
$session->user->email;
$session->organization?->id;        // present when Organizations plugin active
$session->organization?->role;
$session->actor?->onBehalfOf;       // present when Agents plugin active and caller is an agent
```

Server-side API (same operations as the routes, no HTTP hop):

```php
$auth->api()->signUp(email: $email, password: $password);
$auth->api()->organizations()->invite(orgId: $org, email: $email, role: 'member');
```

Laravel: `Polaris::routes()` in a service provider, `auth:polaris` guard, `php artisan polaris:migrations` emits migrations. Symfony: bundle registers an authenticator on the firewall. Same config object, same plugins.

---

## 3. Core interfaces

### 3.1 Entry point

```php
namespace Polaris;

final class Polaris
{
    public static function create(Config|array $config): self;

    public function handler(): \Psr\Http\Server\RequestHandlerInterface;   // mounts all routes under basePath
    public function middleware(): \Psr\Http\Server\MiddlewareInterface;    // session resolution + CSRF
    public function api(): Api;                                             // programmatic access
    public function schema(): Schema;                                       // every table core + plugins need
    public function manifest(): RouteManifest;                              // machine-readable route list
    public function plugin(string $class): Plugin;                          // access a registered plugin
}
```

### 3.2 Plugin contract

```php
namespace Polaris\Contract;

interface Plugin
{
    public function id(): string;                        // 'organizations'
    public function requires(): array;                   // ['email-password'] — resolved at boot, cycle-checked
    public function schema(): Schema;                    // tables THIS plugin owns; prefixed by id; core never mutates them
    public function routes(): iterable;                  // Route objects (see 3.5)
    public function hooks(): iterable;                   // Hook objects: before/after lifecycle events
    public function extensions(): Extensions;            // fields added to User / Session / Account
    public function boot(Runtime $rt): void;             // wire services, read config
}
```

Lifecycle events (PSR-14 dispatched, plugins may veto in `before*`):
`BeforeSignUp, AfterSignUp, BeforeSignIn, AfterSignIn, SessionCreated, SessionRotated, SessionRevoked, BeforeUserUpdate, AfterUserUpdate, BeforeUserDelete, AfterUserDelete, VerificationSent, VerificationConsumed, PasswordChanged, AccountLinked, AccountUnlinked`.

### 3.3 Database adapter

Model/where based so core stays ORM-free. Adapters translate; they never contain auth logic.

```php
namespace Polaris\Contract;

interface DatabaseAdapter
{
    public function findOne(string $model, Where $where, ?Select $select = null): ?Row;
    public function findMany(string $model, Where $where, ?Query $q = null): RowSet;   // limit/offset/sort
    public function create(string $model, array $data): Row;
    public function update(string $model, Where $where, array $data): Row;
    public function updateMany(string $model, Where $where, array $data): int;
    public function delete(string $model, Where $where): void;
    public function deleteMany(string $model, Where $where): int;
    public function count(string $model, Where $where): int;
    public function transaction(callable $fn): mixed;
    public function dialect(): Dialect;                  // for schema export
}
```

`Where` is a small typed AST (`eq`, `in`, `lt`, `gt`, `and`, `or`); no strings.

### 3.4 Other adapters

```php
interface Mailer      { public function send(Email $email): void; }
interface RateStore   { public function hit(string $key, int $limit, int $windowSeconds): RateResult; }   // default: PSR-16 cache
interface SecretStore { public function seal(string $plain, string $context): string; public function open(string $sealed, string $context): string; }
interface Clock       extends \Psr\Clock\ClockInterface {}
interface TemplateRenderer { public function render(string $template, array $vars): RenderedEmail; }   // default: built-in plain templates
```

### 3.5 Route manifest — the piece that makes everything generatable

Every endpoint core or a plugin exposes is a `Route` object, not an anonymous closure:

```php
new Route(
    name:    'organizations.invite',
    method:  'POST',
    path:    '/organizations/{orgId}/invitations',
    input:   InviteInput::class,            // readonly DTO; JSON Schema derived by reflection + attributes
    output:  Invitation::class,
    auth:    Auth::Session,                 // Public | Session | Session+Role | ApiKey | Agent
    effect:  Effect::Write,                 // Read | Write | Destructive
    rateLimit: new Rate(20, 60),
    csrf:    true,
    receipt: true,                          // Agents plugin signs a receipt when the caller is an agent
    handler: [InviteMember::class, 'handle'],
);
```

From the manifest, `polaris manifest` generates: **OpenAPI 3.1**, the **TS client** (`@polaris-auth/client`), a **PHP client**, and an **MCP tool list** so an agent with a valid Polaris token can operate identity through MCP under the same policies. This is the Univeros vocabulary (capability / effect / receipt) applied inside Polaris, so Polaris is later a conforming Univeros app for free.

### 3.6 Schema as data

```php
Schema::define('organization', [
    Field::id(),
    Field::string('name'),
    Field::string('slug')->unique(),
    Field::datetime('createdAt'),
])->index(['slug']);
```

Exported by `polaris schema:export --target=laravel|doctrine|sql:postgres|sql:mysql|sql:sqlite`. `polaris schema:diff` compares the live database to what core + registered plugins require. Never depends on a framework's migration tool; always usable with one.

---

## 4. Session and security model (defaults, all overridable)

- **Sessions**: opaque 256-bit token in an `HttpOnly; Secure; SameSite=Lax` cookie, stored **hashed** (SHA-256) at rest; idle expiry 7 days, absolute expiry 30 days, sliding refresh at most once per hour. Rotation on sign-in, password change, MFA success, and role elevation. Optional device binding (UA + IP prefix) as a plugin.
- **Passwords**: Argon2id with `PASSWORD_ARGON2ID` defaults tuned per environment; transparent rehash on login; breached-password check hook (Cloud service optional).
- **Verification tokens**: single-use, hashed at rest, 15-minute TTL, purpose-bound (`verify-email`, `reset-password`, `magic-link`).
- **CSRF**: double-submit token for cookie sessions; skipped for bearer (API key / agent) auth.
- **Rate limiting**: per-route defaults on sign-in, sign-up, reset, verification; keyed by IP and identifier.
- **Enumeration**: sign-in, reset, and sign-up return identical shapes and timing regardless of whether the account exists.
- **API keys**: `polaris_` prefixed, hashed at rest, scoped, expiring; core feature, not a plugin.
- **Cookies**: signed with `secret`; key rotation supported via `secrets: [current, previous]`.
- **Multi-session**: a user may hold several sessions; list and revoke each.
- **Audit**: every state change dispatches an event with `actor`, `subject`, `ip`, `userAgent`; the Audit plugin persists, core only emits.
- **Headers**: sets `Cache-Control: no-store` on all auth responses.

Security review by an external firm before 1.0. Advisory process, `SECURITY.md`, and coordinated disclosure set up at M1, not at launch.

---

## 5. The Agents plugin (what nobody else ships)

Turns Polaris from "who is this" into "what may this agent do, for whom, within what limits, and prove it."

- **Agent principals**: first-class identity type with owner, scopes, budget, and status.
- **Delegation**: agent tokens carry `act` (on-behalf-of user), scope intersection enforced.
- **Budgets**: calls per window, monetary cap, expiry; decremented per route; `429 BUDGET_EXHAUSTED`.
- **Approvals**: routes marked `Effect::Destructive` (or per-policy) return `202 pending`; approvals inbox API; approver recorded.
- **Receipts**: signed record (Ed25519) of every agent-initiated write, with input/output hashes; verifiable offline; exportable.
- **Earned autonomy**: policy thresholds that relax approval requirements after N clean receipts per route.
- **Federation** (Cloud): trust between Polaris installations so an agent in app A may act in app B with a receipt chain.

---

## 6. Where it beats Better Auth

1. **Route manifest → OpenAPI + TS client + PHP client + MCP tools**, generated, always in sync. Better Auth types flow server→client; Polaris flows server→every consumer, including agents.
2. **Agents as principals** — delegation, budgets, approvals, receipts. Better Auth is starting this post-acquisition; Polaris ships it as the reason to exist.
3. **Schema as data, migration-tool agnostic** with `schema:diff`. Adapters emit native migrations rather than requiring one tool.
4. **Adapter conformance suite** — every framework and database adapter passes the same black-box tests, so "works with Laravel" means the same thing as "works with Symfony." Better Auth's adapters vary in quality.
5. **Passkeys and API keys in the first release, not late plugins**; enumeration-safe by default; hashed session and verification tokens at rest.
6. **`polaris/testing`** — in-memory adapters, fake mailer, controllable clock, so app test suites don't need a database or SMTP to test auth flows.

---

## 7. Extraction from the existing Polaris module

The current Univeros Polaris module already has identity, MFA, and multi-tenant RBAC. Plan:

1. Draw the line between framework-free logic and Univeros-specific glue (container, routing, DTO conventions).
2. Move framework-free logic into `polaris/core` behind the interfaces in §3; Univeros glue becomes the `psr15` adapter plus a thin Univeros package.
3. RBAC becomes the `organizations` plugin's role model plus a core `Permission` check; tenant id lives on `Session`.
4. The MFA code becomes `plugin-totp` (and seeds `plugin-passkey`).
5. Univeros PHP consumes `polaris/core` like any other app. If that migration hurts, the interfaces are wrong — fix them before Laravel sees them.

---

## 8. Roadmap

| Milestone | Scope | Exit criterion |
|---|---|---|
| **M0 — Spec & extraction** (wks 1–3) | Interfaces in §3 frozen as code; schema-as-data; route manifest; extraction plan executed on the existing module | Univeros runs on `polaris/core` |
| **M1 — Core** (wks 4–8) | Email/password, sessions, verification, reset, API keys, CSRF, rate limiting; `pdo`; `psr15`; `testing`; CLI `init/doctor/schema:*` | Slim demo app; adapter conformance suite green on Postgres/MySQL/SQLite |
| **M2 — Plugins & client** (wks 9–14) | Social, passkeys, TOTP, organizations, magic link; `client-js` generated from manifest; OpenAPI | Next.js/Vite demo consuming the TS client |
| **M3 — Frameworks & 1.0** (wks 15–18) | `laravel`, `symfony` adapters; `adapter-doctrine`, `adapter-eloquent`; docs; external security review; advisory process | 1.0 tag; Laravel and Symfony starter kits |
| **M4 — Commercial & agents** (post-1.0) | Yii adapter; Agents plugin; SSO, SCIM, Admin, Audit; license-key service shared with Vela billing | First paying instance |

Team: one senior PHP engineer full time (the author), a second from M2 for adapters and docs, security firm at M3.

---

## 9. Decisions needed now

- npm scope (`@polaris-auth/*` or similar); Packagist vendor `polaris/` is settled.
- Minimum PHP: 8.3 (readonly classes, typed constants) or 8.4 (property hooks, lazy objects — nicer DX, smaller install base today).
- Commercial license: BSL 1.1 vs Elastic License 2.0 for paid plugins.
- Organizations in core or plugin. Recommendation: plugin, but `Session` reserves a nullable `organization` slot so core code paths are tenant-aware.
- Whether `client-js` also ships React/Vue hooks at 1.0 or only the framework-free client. Recommendation: framework-free only; hooks as community packages.
