# Polaris for PHP — Program 4: "Better Auth for PHP"

**Repository:** `univeros/polaris-core` (existing monorepo; this is `docs/better/spec.md`, program 4)
**Status:** Draft 2 — 2026-10-09 (defaults for the owner's questions applied, see §9)
**Starting point:** 0.6.1 — core (52 routes, contract-frozen), four hosts, the six infrastructure packages, `@polaris-auth/client` on npm
**Goal:** Polaris can be pitched, installed and operated as *the* Better Auth of PHP — feature parity on sign-in methods and OAuth/MCP, an agent-native layer Better Auth does not have, and a developer surface an AI coding agent can drive end to end without a human reading docs.

---

## 0. Decisions this spec assumes

1. **No new repository for code.** Every package below is a plugin on `Polaris\Contract\Plugin`, in `packages/<id>`, mirrored to `univeros/polaris.<id>`, published as `polaris/<id>` at the monorepo version. The agent SDKs (`packages/agent-ts`, `packages/agent`) and the Claude Code plugin (`plugins/claude-code/`) live here too. The only repository that changes besides this one is the website (`polaris.univeros.io`).
2. **Core stays frozen.** The 52 routes do not change. Every new sign-in method mints sessions through the seam `polaris/sso` already uses (`TokenService::mint(principal, sessionId, extra)`, `AccessTokenClaims::$extra`, the one-minute code exchange for browser hand-offs). User identifiers a plugin needs (`username`, `phone`, `is_anonymous`) are side tables owned by the plugin, never columns on `auth_users` (the WP0 decision of program 3). Ids are UUID v7 like the rest of Polaris. Anything else core must expose is logged in `docs/better/decisions.md` first, as before; the one such seam this program already knows it needs is listed in §9.
3. **Same bar as programs 1–3.** PSR-only imports, allowed dependencies listed per package in §3, endpoints declared in `api/<id>/**/*.yaml`, RFC 9457 problems at `https://polaris.univeros.io/problems/<id>/<name>`, recorded fixtures replayed through the four hosts, a client namespace per plugin generated from the manifest, `composer qa` green, decisions appended to `docs/better/decisions.md`.
4. **Nothing paid, nothing hosted.** Polaris Cloud stays deferred; this program adds no seam that only a hosted service could fill. The one soft dependency on the site is the problem-type URLs, which already exist.
5. **Billing is out of scope.** Better Auth's six payment plugins (Stripe, Polar, Autumn, Creem, Dodo, Commet) are not matched here. When a billing package exists it is its own program; nothing in this one depends on it.

---

## 1. Positioning and the migration map

The pitch is one sentence: *Polaris is Better Auth for PHP — the same embed-it-in-your-app model, every feature open source, running in Laravel, Symfony, Yii or any PSR-15 host, and built for agents from the start.*

The migration map is a page on the site and a section of the README. Every Better Auth plugin must resolve to a Polaris package and a status; "not planned" is an allowed status, a blank is not.

| Better Auth | Polaris package | Status after this program |
|---|---|---|
| core (email/password, sessions, social) | `polaris/core` + `polaris/social` | shipped + §3.1 |
| Two-Factor | `polaris/core` (TOTP, SMS, email, recovery, step-up) | shipped |
| Passkey | `polaris/passkey` | §3.2 |
| Magic Link, Email OTP, Phone Number, One-Time Token | `polaris/passwordless` | §3.3 |
| Username | `polaris/username` | §3.4 |
| Anonymous | `polaris/anonymous` | §3.4 |
| Multi Session, Last Login Method | `polaris/multi-session` | §3.4 |
| One Tap, Generic OAuth, OAuth Proxy | `polaris/social` | §3.1 |
| Admin | `polaris/admin` | shipped |
| Organization (orgs, teams, members) | `polaris/core` (orgs, roles, invites) | shipped; teams not planned (org-scoped roles cover the use; reversible as a package) |
| SSO, SCIM | `polaris/sso`, `polaris/scim` | shipped |
| API Key | `polaris/api-keys` | §3.5 |
| JWT, Bearer | `polaris/core` (JWT access tokens, JWKS) | shipped |
| OAuth 2.1 Provider, OIDC, Device Authorization | `polaris/oauth-provider` | §3.6 |
| MCP | `polaris/mcp` | §3.7 |
| Agent Auth (unstable) | `polaris/agents` | §4 — superset, protocol-compatible |
| Captcha, Have I Been Pwned | `polaris/sentinel` | shipped |
| i18n | `polaris/messaging` (templates); problem titles: §6 | shipped / §6 |
| Open API | `polaris/cli` (`manifest --format=openapi`) | shipped |
| Test Utils | `polaris/testing` | shipped |
| Sign In With Ethereum | — | not planned |
| Stripe, Polar, Autumn, Creem, Dodo, Commet | — | separate program |
| Dub | — | not planned |
| Infrastructure (paid): dashboard API, audit, log drains, abuse protection, email/SMS | `polaris/admin`, `polaris/audit`, `polaris/sentinel`, `polaris/messaging` | shipped, open source |

---

## 2. Where Polaris is better, in writing

These are the claims the site and README will make; each must be true at the end of the program and provable by a link into the repository.

1. **Every response is contract-frozen.** 184 core fixtures plus each package's, replayed through four HTTP kernels in CI. Better Auth has unit tests; it has no replayed cross-host contract.
2. **One auth stack, four frameworks.** Laravel, Symfony, Yii and plain PSR-15 run the same bytes. Better Auth is TypeScript-runtime only.
3. **The infrastructure tier is free.** Dashboard API, audit log with hash chain, log drains, risk engine, SSO self-service, SCIM — all open source and self-hosted.
4. **Agents are principals, not an afterthought.** Delegation with `act` claims, capability grants with budgets and constraints enforced centrally, approvals with three methods, signed receipts, a kill switch (§4). Better Auth's Agent Auth is marked unstable, makes the app render approvals, and skips its own checks on per-capability routes.
5. **Polaris is itself an MCP server.** Every endpoint and every CLI command is a tool an agent can call under the principal's own permissions (§3.7).
6. **An agent can install it blind.** `polaris init --host=laravel --plugins=... --json` and `polaris add <plugin>` are idempotent and print what they changed; every command has `--json`; every problem type resolves to a machine-readable remedy (§6).
7. **Errors are a standard.** RFC 9457 everywhere in the packages, one `type` URL per failure, documented and resolvable.
8. **No container, no magic.** `Polaris::create(new Config(...))` builds the whole graph explicitly; the TypeScript client and the MCP tools are generated from the same manifest, so types never drift from the server.

---

## 3. Track A — parity packages

Dependency rules per package follow §2 of the plugin docs: PSR interfaces, `polaris/core`, and only the libraries named here.

### 3.1 `polaris/social`

OAuth 2.0 / OIDC sign-in and account linking.

**Tables:** `polaris_social_account` (id, user_id, provider, provider_account_id, email, email_verified, scopes, access_token_enc, refresh_token_enc, expires_at, id_token_claims_hash, created/updated; unique provider+provider_account_id), `polaris_social_state` (state, provider, pkce_verifier_enc, redirect_uri, link_user_id?, expires) — or the cache when one is configured.

**Providers:** a `Provider` interface (authorization URL, token exchange, profile fetch, id-token verification) with a built-in catalog: Google, Apple, Microsoft (Entra, personal), GitHub, GitLab, Discord, Facebook, X, LinkedIn, Slack, Twitch, Spotify, Zoom, Notion, Dropbox, Reddit, Kick, TikTok, Hugging Face. `GenericOAuth` covers any other OAuth 2 server (`authorization_code` + PKCE, optional OIDC discovery, custom profile mapping). Apple's client-secret JWT and Google One Tap's ID-token path are provider-specific features of their classes, not separate plugins.

**Routes (`/social`):** `POST /social/{provider}/start` → `{url, state}` (body: `redirect_uri`, `scopes?`, `link: bool`); `GET /social/{provider}/callback` → `302 redirect_uri?code=` then `POST /social/exchange` → core login envelope (the SSO hand-off pattern, reused verbatim); `POST /social/google/one-tap` (credential → envelope); `GET /social/accounts`; `POST /social/{provider}/link` (requires step-up); `DELETE /social/{provider}` (refused when it is the user's last credential); `POST /social/{provider}/token` → a fresh provider access token for the user (refreshes if expiring), so an app can call GitHub or Google on the user's behalf.

**Linking policy (config):** `trustedProviders: ['google', 'apple']` auto-link to an existing user by verified email; untrusted providers must link from a session; `allowDifferentEmails` per provider. Sign-up through social creates a verified user with `password_hash = NULL` (already allowed by the schema) and `amr: ["social:<provider>"]`.

**OAuth proxy:** `proxy: ['https://auth.example.com']` — preview and local origins start the flow through a stable origin that validates a signed `return_to` and forwards the code; what Better Auth ships for Vercel previews, host-neutral.

**Dependencies:** PSR-18/17, `firebase/php-jwt` (JWKS, as in `polaris/sso`). Events: `social.linked`, `social.unlinked`, `social.signed_in`, `social.signed_up`, `social.token_refreshed`.

### 3.2 `polaris/passkey`

WebAuthn Level 3 through `web-auth/webauthn-lib` behind `Polaris\Passkey\Protocol`.

**Table:** `polaris_passkey` (id, user_id, credential_id, public_key, counter, aaguid, transports, backed_up, name, last_used_at, created).

**Routes (`/passkey`):** `POST /passkey/register/options` + `POST /passkey/register/verify` (session required; discoverable credentials requested by default); `POST /passkey/authenticate/options` (anonymous; empty `allowCredentials` for conditional UI/autofill) + `POST /passkey/authenticate/verify` → core login envelope with `amr: ["passkey"]`, `mfa: true` when configured as a strong factor; `GET /passkey/list`, `PATCH /passkey/{id}` (rename), `DELETE /passkey/{id}`.

**Three roles for one credential:** primary sign-in; a core MFA factor type `passkey` registered through a factor-type seam (`MfaFactorTypeInterface` + `Config` registration — the one core change this program plans, decision #1 in `decisions.md`; the plugin owns verification, core owns the factor row and the challenge flow); and an approval strength for `polaris/agents` (§4.4). Relying-party id and origins come from config; mismatches are `passkey/origin_mismatch`.

### 3.3 `polaris/passwordless`

Four sign-in methods that share one service: send a secret, verify it, mint a session.

- **Magic link:** `POST /magic-link/send` (email, `redirect_uri`) → `GET /magic-link/verify?token=` → `302 redirect_uri?code=` → `POST /magic-link/exchange`. Tokens hashed, 15 min, single use.
- **Email OTP sign-in:** `POST /email-otp/send`, `POST /email-otp/verify` → envelope. Also `POST /email-otp/verify-email` and `POST /email-otp/reset-password` as OTP alternatives to core's link flows (core's routes untouched).
- **Phone:** `POST /phone/send`, `POST /phone/verify` → envelope; table `polaris_phone` (user_id, e164, verified_at; unique). A phone is a second verified contact of an existing user and a sign-in identifier for it; it is not a sign-up identifier (`auth_users.email` stays required and unique, no placeholder emails). `POST /phone/add` + `POST /phone/confirm` from a session attach it.
- **One-time token:** `POST /one-time-token/generate` (session) → `POST /one-time-token/verify` → envelope. Cross-domain and native-app session transfer.

All sends go through `polaris/messaging` templates (`email.magic_link`, `email.otp`, `sms.otp` exist) and `MessagePolicy` rate limits; sentinel guards the send routes like core's. Unknown identifiers get the same response as known ones (anti-enumeration carried over from core).

### 3.4 `polaris/username`, `polaris/anonymous`, `polaris/multi-session`

Three small packages, named after their Better Auth counterparts so the migration map is one-to-one.

- **username:** table `polaris_username` (user_id, username, display_username; unique, case-insensitive). `POST /username/sign-in` (username or email + password → core login path), `PATCH /username` (session), validation rules (length, charset, reserved list) in config. Core's `/auth/login` is untouched; the plugin's route resolves the email and delegates.
- **anonymous:** `POST /anonymous/sign-in` → a guest user (`polaris_anonymous`: user_id, created, converted_at), `amr: ["anonymous"]`, no org; conversion on sign-up/social/passkey from a guest session moves data through an `onConvert` hook the host implements; pruning of unconverted guests by `polaris anonymous:prune`.
- **multi-session:** several signed-in accounts in one browser. `GET /multi-session/list` (device cookie → sessions), `POST /multi-session/switch` (issues the envelope for another account already on this device), `DELETE /multi-session/{sessionId}`. Last-login-method is a field on the device record (`polaris_device`: device_id, user_id, last_method, last_seen) the client reads to pre-select the button.

### 3.5 `polaris/api-keys`

End-user and organization API keys (not the operator keys of `polaris/admin`).

**Table:** `polaris_api_key` (id, owner_type user|organization, owner_id, name, prefix `pk_live_`/`pk_test_` (the operator keys of `polaris/admin` keep `pak_`), key_hash (keyed, pepper context `api_key`), permissions (subset of the owner's), rate_limit (window, max), expires_at, last_used_at, metadata json, revoked_at).

**Routes (`/api-keys`):** CRUD, `POST /api-keys/{id}/rotate` (old key valid for a grace window), `POST /api-keys/verify` (server-side check returning owner and permissions, for apps that proxy). The plugin middleware accepts `Authorization: Bearer pk_...` or `x-api-key` on every Polaris route and resolves a principal whose permissions are the key's intersection with the owner's; core's authorization layer then applies as if it were a session. Every use with `remaining` headers; every creation/rotation/revocation audited.

### 3.6 `polaris/oauth-provider`

Polaris as an OAuth 2.1 and OpenID Connect provider.

**Tables:** `polaris_oauth_client` (id, owner org?, name, client_id, client_secret_hash?, type confidential|public, redirect_uris, grant_types, scopes, token_endpoint_auth_method, jwks or jwks_uri, dpop_bound_access_tokens, trusted (skips consent), logo, policy_uri, created_by), `polaris_oauth_consent` (user, client, scopes, granted_at), `polaris_oauth_code` (hashed, pkce, nonce, expires, used), `polaris_oauth_token` (jti, client, user?, scopes, dpop_jkt?, expires, revoked; refresh tokens keyed-hashed, rotating), `polaris_oauth_device_code` (device/user codes, interval, status), `polaris_oauth_ciba_request` (auth_req_id, client, login_hint, binding_message, status).

**Endpoints:** `GET /oauth2/authorize` (returns consent data as JSON for XHR clients, or `302` to the host's consent page; `POST /oauth2/authorize/decision` records it), `POST /oauth2/token` (authorization_code + PKCE, refresh_token, client_credentials, device_code, `urn:openid:params:grant-type:ciba`, `urn:ietf:params:oauth:grant-type:token-exchange` for §4), `GET|POST /oauth2/userinfo`, `POST /oauth2/revoke`, `POST /oauth2/introspect`, `POST /oauth2/register` (RFC 7591 DCR, **off by default**), `POST /oauth2/device/code`, `GET /oauth2/device/verify` (user-code page data) + `POST /oauth2/device/approve`, `POST /oauth2/ciba` (backchannel request), `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server` (RFC 8414). JWKS is core's existing `/auth/jwks`; access tokens are signed by core's keys with `aud` = resource, `scope`, `client_id`, `cnf.jkt` when DPoP-bound (RFC 9449).

**Scopes = permissions.** A scope is a core permission name or a plugin's (`openid`, `profile`, `email` map to claims). Consent screens are the host's HTML; the package ships the data endpoints and `examples/*/consent.php`. Client management: `/orgs/{id}/oauth/clients` (org self-service) and `/admin/oauth/clients`. Client ID Metadata Documents (CIMD, the MCP 2026-07 profile) are supported: a `client_id` that is an `https` URL is fetched (special-use addresses rejected), cached and validated instead of registered.

**Dependencies:** `lcobucci/jwt` (core's), PSR-18, `firebase/php-jwt` for client assertions. No `league/oauth2-server`: its storage interfaces fight the plugin schema contract and its entity model duplicates core's users; decision to be recorded with the reasoning in `decisions.md`.

### 3.7 `polaris/mcp`

Two halves in one package because they share token verification.

**Protect an MCP server with Polaris.** `McpProtectedResource` PSR-15 middleware for any PHP MCP server: verifies access tokens against JWKS locally (signature, issuer, audience, expiry), enforces DPoP binding, answers `401` with `WWW-Authenticate: Bearer resource_metadata="..."` and `403 insufficient_scope` with the missing scopes so clients step up; serves `GET /.well-known/oauth-protected-resource` (RFC 9728). Works in the same process as `polaris/oauth-provider` or against a remote issuer (`issuer`, `jwksUri` config). Protocol versions: the 2026-07-28 profile by default; `legacy: reject|allow` for the 2025 session-based one.

**Polaris as an MCP server.** `McpServer` built from the manifest: every Polaris endpoint (core and plugins) becomes a tool named by its route name (`polaris.auth.me`, `polaris.orgs.members.list`, `polaris.admin.users.ban`) with the endpoint's input rules compiled to a JSON Schema and the response schema from OpenAPI; tools are listed per principal (a user agent sees what its permissions allow, an operator key sees `admin.*`). CLI commands become tools too (`polaris.schema.diff`, `polaris.doctor`, `polaris.manifest`) over the stdio transport only. Transports: `bin/polaris mcp` (stdio, local coding agents) and `POST /mcp` (Streamable HTTP through the pipeline, protected by the middleware above). Resources: `polaris://manifest`, `polaris://schema`, `polaris://problems/<type>`. Built on the official `mcp/sdk` (modelcontextprotocol/php-sdk) behind `Polaris\Mcp\Transport`; decision recorded.

---

## 4. Track B — `polaris/agents`

The package that makes "agent-native" a feature list instead of a slogan. Wire-compatible with Better Auth's Agent Auth Protocol discovery and execution shapes where they are defined, stricter everywhere they are not.

### 4.1 Model

- **Agent** (`polaris_agent`): id, owner_type user|organization, owner_id, name, mode `delegated|autonomous`, host_id?, auth `private_key_jwt|client_secret|delegated_token`, public JWK or secret hash, status active|suspended|revoked, created_by. A delegated agent acts *for* its owner; an autonomous one acts *as itself* with its own permissions.
- **Host** (`polaris_agent_host`): a runtime that enrolls agents (a Claude Code install, a Vela worker, a cron box): id, owner, name, enrollment token hash, default capability policy.
- **Capability**: declared in config (`name`, `description`, JSON-Schema `input`, required `permission`, `risk: low|medium|high`, optional `location` route), published by discovery and as MCP tools automatically.
- **Grant** (`polaris_agent_grant`): agent, capability, `constraints` (allowed argument patterns, rate, `budget: {count|amount, window}`), granted_by, approved_via, expires, revoked.
- **Approval** (`polaris_agent_approval`): a pending grant request: method `device_code|ciba|in_app`, strength `session|step_up|passkey`, user_code, binding message, status, decided_by.
- **Receipt** (`polaris_agent_receipt`): one per execution: agent, grant, capability, input hash, outcome, budget_before/after, prev_hash, hash, signature (core key). Verifiable at `GET /agents/receipts/{id}/verify`; exportable as a chain.

### 4.2 Discovery and registration

`GET /.well-known/agent-configuration` (served at the app root; the adapters register it outside the base path): `issuer`, `endpoints` (register, capabilities, grants, approvals, execute, session, receipts, mcp), `default_location`, `modes`, `approval_methods`, `approval_strengths`, `token_endpoint` (the OAuth one, §3.6), `agent_sdk_versions`. `GET /agents/capabilities` lists capabilities (with `location` when set) and the permission each requires.

Registration is explicit: `POST /agents/register` (by a user or org admin session: name, mode, JWK or request a secret) or `POST /agents/enroll` (by a host with its enrollment token: creates an agent under the host's default policy). Both emit `agent.registered` / `agent.enrolled`; an `AgentApprovalRequired` policy can make registration itself an approval.

### 4.3 Authentication of agents

Three ways, all ending in a core access token whose claims carry the actor:

1. **OAuth client credentials / private_key_jwt** at `/oauth2/token` → `sub = agent`, `actor_type = agent`.
2. **Delegation by token exchange** (RFC 8693): a user session exchanges for an agent token with `sub = user`, `act: {sub: agent, type: agent}`; everything downstream — core RBAC, audit, admin — sees the user *and* the agent. Scoped by the grant, shorter-lived than the session, revoked with it.
3. **Signed request JWTs** (Agent Auth Protocol compatible): `aud` = the exact URL called, `jti` replay-checked, `exp` ≤ 5 min, optional request-binding claims (`htm`, `htu`, body hash); verified by `AgentRequestMiddleware`.

### 4.4 Grants, approvals, budgets

`POST /agents/grants/request` (agent → capability, constraints asked) creates an approval. Methods: **device_code** (user visits the host's page, enters the code; the page's data comes from `GET /agents/approvals/{code}`), **ciba** (push through `polaris/messaging` to the owner; `POST /agents/approvals/{id}/decide`), **in_app** (the owner's own client lists `GET /agents/approvals` and decides). Strength is policy per capability risk: `high` requires passkey or step-up. A policy can auto-approve (`risk: low` under a default budget) so a developer's agent is not blocked on day one.

Budgets are decremented atomically in the execution transaction; exhaustion answers `agents/budget_exhausted` and emits the event; a refill is a new approval.

### 4.5 Execution

- Capabilities without `location`: `POST /agents/execute {capability, input}` — grant intersected with token claims, constraints evaluated, budget consumed, `onExecute` handler called, receipt written, all in one unit of work.
- Capabilities with `location`: the same checks run in `AgentRequestMiddleware` **before** the host's route, so a capability-bound route cannot skip them; the handler receives the evaluated grant in a request attribute. This closes the gap Better Auth documents.
- `GET /agents/session` returns the agent, mode, owner, active grants and remaining budgets.
- MCP: every capability is also a tool on `/mcp` (§3.7); an MCP call is an execution, same receipt.

### 4.6 Control

Owners and org admins: `GET /agents`, `GET /agents/{id}`, `POST /agents/{id}/suspend|resume`, `POST /agents/{id}/revoke` (kill switch: tokens, grants, pending approvals ended; receipts sealed with a final checkpoint), `GET /agents/{id}/receipts`, `DELETE /agents/grants/{id}`. Operators: `/admin/agents/*` across the instance. Events: `agent.registered|enrolled|suspended|resumed|revoked`, `agent.grant.requested|approved|denied|revoked|exhausted`, `agent.executed|execution_denied`, `agent.receipt.sealed`.

### 4.7 SDKs

- `@polaris-auth/agent` (`packages/agent-ts`): discover, register/enroll, request a grant, poll an approval, sign request JWTs, call capabilities, verify receipts. Node and edge.
- `polaris/agent` (`packages/agent`, PHP): the same for PHP agents and for Univeros/Altair services calling each other.
- Both generated where possible from the manifest, hand-written only for the signing and polling loops.

---

## 5. Client and host surface

- `@polaris-auth/client`: a namespace per new plugin (`client.social`, `client.passkey`, `client.passwordless`, `client.username`, `client.anonymous`, `client.multiSession`, `client.apiKeys`, `client.oauth`, `client.agents`), generated as today. Passkey needs a thin hand-written browser helper for `navigator.credentials` (the only non-generated code besides the sentinel retry).
- `@polaris-auth/react`: `useSession`, `useOrganization`, `useAgents`, `SignIn` headless hooks over the client. Small, optional, no UI components — a component library is a later repository if ever.
- Adapters: each new plugin registers through the existing `plugins` configuration in Laravel/Symfony/Yii; `social`, `passkey`, `passwordless` and `oauth-provider` ship a route for their browser callbacks outside the API prefix where the host needs it, declared in the package README. `examples/*` gain the consent page, the device-code page and the agent approval page as the reference HTML.

---

## 6. Track C — agent-accessible developer experience

What makes an AI coding agent able to install, configure, diagnose and promote Polaris without a human.

1. **`polaris init`** (`polaris/cli`): `--host=slim|laravel|symfony|yii`, `--plugins=social,passkey,...`, `--database=pgsql|mysql|sqlite`, `--json`, `--dry-run`. Detects the host when omitted, writes config, env keys, migrations/schema, the route registration, the client install line; idempotent; prints a change list and the next command. `polaris add <plugin>` does the same for one package.
2. **`--json` on every command**, including `doctor`, whose findings carry `id`, `severity`, `remedy` (a command or a config line) and the problem-type URL.
3. **Problem types resolve.** `https://polaris.univeros.io/problems/<plugin>/<name>` answers HTML to a browser and JSON (`type`, `title`, `cause`, `remedy`, `docs`) to `Accept: application/json`; the site builds these pages from a `problems.yaml` the CLI exports (`polaris manifest --format=problems`), so a new problem type without an entry fails CI.
4. **Skills.** `skills/<package>/SKILL.md` for every package (install, configure, common tasks, the problem types and their fixes), checked in, and published together as the `polaris` Claude Code plugin (`plugins/claude-code/`: the skills plus the MCP server definition `bin/polaris mcp`) and to skills.sh and the agent-skills directories. `AGENT.md` gains a section per package and points at the skills.
5. **The site.** `llms.txt` (index with one line per page) and `llms-full.txt` regenerated from the repository's docs at every tag by CI — today's copy is at 0.1.0, has no plugin, no client and no index. The migration map (§1), the comparison (§2) and the per-package pages are generated from `status.json` as before, with the version badge read from the latest tag.
6. **Manifest formats.** `polaris manifest --format=openapi|json|mcp-tools|problems|skills`; the TypeScript client, the MCP tool list, the problem pages and the skill reference sections all derive from it, drift-checked in CI.
7. **The demo.** `examples/slim` and `walkthrough.sh` gain social (a local fake provider), passkey (virtual authenticator in Playwright), magic link, an OAuth client, an MCP client call and an agent enrolling, requesting a grant, getting auto-approved and producing a receipt — the end-to-end an agent can run to see it work.

---

## 7. Cross-cutting requirements

- **Security review** before 1.0.0 extends to `social`, `passkey`, `oauth-provider`, `mcp`, `agents` (the four infrastructure packages were already scoped). `passwordless`, `api-keys` and the three small packages are in scope at the reviewer's discretion.
- **Secrets:** provider tokens, API keys, client secrets, enrollment tokens, agent secrets — encrypted or keyed-hashed through core's encrypter, never logged, never returned after creation (API keys and secrets shown once).
- **Anti-enumeration** holds on every new send/verify route exactly as core's.
- **Problem types** (new): `social/*`, `passkey/*`, `passwordless/*`, `username/*`, `anonymous/*`, `multi-session/*`, `api-keys/*`, `oauth/*` (RFC 6749 error codes mapped), `mcp/*`, `agents/*`; each with a page (§6.3).
- **Fixtures:** every package records its fixtures; CI replays all through PSR-15, Laravel, Symfony, Yii. Browser-dependent steps (passkey, consent redirects) are fixtures at the HTTP boundary with the browser side covered by the Playwright suite of the demo.
- **Docs:** a README per package in the shape of the existing ones; `docs/better/` holds this spec, `decisions.md`, and the Agent Auth Protocol compatibility notes.

---

## 8. Work packages

One WP per release; branch `better/wpN` from `main`; one pull request listing each acceptance criterion with how it was verified; decisions appended to `docs/better/decisions.md`. Every WP also: adds its packages to `packages/client-ts/polaris.php` and regenerates the client, adds a README per package, adds the package to the root README table, records its fixtures and replays them through the four harnesses, and leaves `composer qa` green.

### WP1 — passwordless, username, anonymous, multi-session (0.7.0)

Scope: §3.3, §3.4. Dependencies: `polaris/core`, `polaris/messaging`.

Acceptance:
1. Magic link, email OTP, one-time token and phone sign-in each end in core's login envelope with the right `amr`; a second use of any secret is refused; unknown identifiers get the same response as known ones.
2. `polaris/username`: sign-in by username or email through core's password path; validation rules from config; case-insensitive uniqueness proven on PostgreSQL, MySQL and SQLite.
3. `polaris/anonymous`: a guest session, conversion through `onConvert` keeps the guest's id reachable to the host, `anonymous:prune` removes unconverted guests older than the policy.
4. `polaris/multi-session`: two accounts on one device, switch issues a fresh envelope without re-authentication, revoke of one leaves the other; `last_method` readable by the client.
5. Sentinel's guarded-route list covers the new send routes (configuration, not a core change).

### WP2 — social, passkey (0.8.0)

Scope: §3.1, §3.2. Dependencies: PSR-18/17, `firebase/php-jwt`, `web-auth/webauthn-lib`.

Acceptance:
1. Google, GitHub, Apple and Microsoft sign-in and linking against recorded provider responses; `GenericOAuth` against the Slim demo's own fake provider; One Tap verifies an ID token offline against a recorded JWKS.
2. Linking policy: trusted provider auto-links by verified email; untrusted requires a session; unlinking the last credential is refused (`social/last_credential`).
3. The OAuth proxy forwards a code from a preview origin with a signed `return_to` and refuses an unsigned one.
4. Passkey registration, discoverable authentication and conditional-UI options recorded at the HTTP boundary; the browser side covered by a Playwright run in `examples/slim` with a virtual authenticator.
5. Passkey as MFA factor: enroll, challenge and verify through core's MFA routes with factor type `passkey`; decision #1 logged; core's 184 fixtures still replay unchanged.

### WP3 — api-keys, oauth-provider (0.9.0)

Scope: §3.5, §3.6.

Acceptance:
1. API keys resolve a principal on every Polaris route (core and plugin) with permissions intersected with the owner's; rate limit and expiry enforced; rotate keeps the old key for the grace window; secrets shown once.
2. OAuth: authorization code + PKCE (S256 required), refresh rotation, client credentials, device grant, CIBA and token exchange each pass a conformance fixture set; DCR off by default and refused when off; CIMD client ids fetched, cached and validated, special-use addresses rejected.
3. DPoP-bound tokens carry `cnf.jkt`; replay of a DPoP proof is refused.
4. `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` advertise exactly what is enabled; `/auth/jwks` is reused unchanged.
5. Scopes resolve to core permissions; a trusted client skips consent; the consent decision is recorded and revocable.

### WP4 — mcp, agents, agent SDKs (0.10.0)

Scope: §3.7, §4, `packages/agent-ts`, `packages/agent`. Dependencies: `mcp/sdk`.

Acceptance:
1. `McpProtectedResource` accepts a valid token, answers 401 with `resource_metadata` without one, 403 `insufficient_scope` with the missing scopes; works against a remote issuer in a test.
2. `bin/polaris mcp` lists one tool per endpoint the principal may call, with JSON Schemas derived from the manifest; a tool call produces the same response as the HTTP route (asserted against the fixtures).
3. Agents: register, enroll, request a grant, approve by each of the three methods, execute with and without `location`, budget exhaustion, revoke — every step a fixture; a capability with `location` cannot be reached without passing `AgentRequestMiddleware`.
4. Receipts form a verified hash chain per agent; `verify` detects a modified receipt; revoke seals the chain.
5. Token exchange yields `act` claims that `polaris/audit` records as `actor_type = agent` with the user as subject.
6. `/.well-known/agent-configuration` validates against `agent-auth-compat.md`; `@polaris-auth/agent` and `polaris/agent` complete the enrol-to-receipt walkthrough against the Slim demo.

### WP5 — developer surface (0.11.0)

Scope: §5 (`@polaris-auth/react`), §6.

Acceptance:
1. `polaris init --host=<each of four> --plugins=social,passkey,passwordless --json --dry-run` on a fresh host returns the change list and exit 0; without `--dry-run` the host boots and `walkthrough.sh` passes; a second run changes nothing.
2. `polaris add <plugin>` is idempotent; every CLI command accepts `--json`; `doctor --json` findings carry `remedy`.
3. `polaris manifest --format=problems` lists every problem type emitted in the repository (a grep-based test fails on an undocumented one); the site answers JSON for each with `Accept: application/json`.
4. `skills/<package>/SKILL.md` exists for every package; `plugins/claude-code/` installs and exposes the skills plus the MCP server; a Claude Code session with the plugin completes `init` on a fresh Laravel app from the prompt "add Polaris with passkeys and Google sign-in".
5. The site's `llms.txt` and `llms-full.txt` are generated from the repository at tag time and include every package, the client and the migration map; the version badge reads the tag.
6. `@polaris-auth/react` hooks typed from the client, tested with a fake fetch.

### WP6 — 1.0.0

Acceptance: external security review findings closed for `social`, `passkey`, `oauth-provider`, `mcp`, `agents` and the four infrastructure packages; the migration map has no blank; every package's fixtures are part of the contract freeze; `CHANGELOG.md` carries the 1.0 entry; `univeros/polaris` 2.0 can be rebuilt on the released set (verified in its own repository, not here).

---

## 9. Decisions taken by default, and what is left open

Applied in this draft, to be confirmed in review of the drop (changing one amends the spec, not the program):

1. **Teams: not planned.** Org-scoped roles cover the use; a `polaris/teams` package can follow without touching anything here.
2. **Passkey as MFA factor: accepted**, with one core seam (a factor-type registration) logged as decision #1 of this program when WP2 opens it.
3. **Phone: second verified contact only**, never a sign-up identifier; no placeholder emails.

Left to the WPs and logged in `decisions.md` when taken:

4. OAuth provider written fresh behind interfaces (proposed) or `league/oauth2-server` adapted to the plugin schema.
5. `mcp/sdk` as a hard dependency of `polaris/mcp`, or only of its server half.
6. Agent Auth Protocol: exact compatibility with Better Auth's shapes or a Polaris protocol document with a compatibility mode (`agent-auth-compat.md` holds the current mapping).
7. Claude Code plugin publication: the `univeros` marketplace or a `polaris-auth` one matching the npm scope.
