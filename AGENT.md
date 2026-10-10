# AGENT.md — univeros/polaris-core (Polaris for PHP)

Orientation for coding agents working in this repository. Read this before editing. The identity design lives in `docs/auth/`; task 1 (the extraction, complete) lives in `docs/extraction/`, task 2 (the framework adapters, complete) in `docs/adapters/`, the infrastructure program (six packages on the plugin runtime, complete) in `docs/plugins/`, program 4 ("Better Auth for PHP": sign-in methods, OAuth/MCP provider, agents, the developer surface; in progress) in `docs/better/`.

This repository (`github.com/univeros/polaris-core`) publishes the `polaris/*` Composer packages. It was seeded from `univeros/polaris` v1.0.0. **`univeros/polaris` is a different repository and must never be modified from here.** It remains the Univeros module for Univeros hosts; this repository is the framework-agnostic Polaris for PHP.

## Status

- **The code is the complete Polaris 1.0.0** (June 2026): authentication, MFA/OTP, sessions and rotating refresh tokens, multi-tenant organizations and RBAC, audit log, 35 PSR-14 events, 52 endpoints specified in `packages/core/api/**/*.yaml`, 115 test files.
- **Extraction (task 1) is complete.** The monorepo holds `packages/core` (`Polaris\`, framework-free), `packages/psr15`, `packages/pdo`, `packages/testing`, `packages/cli`; nothing imports `Altair\`, `Cycle\` or `Univeros\` any more (`bin/check-imports` blocks it). The spec was `docs/extraction/spec.md`; the decisions taken along the way are in `docs/extraction/decisions.md`, the one behaviour change in `behaviour-changes.md`; the Slim demo is `examples/slim`.
- **Framework adapters and the TypeScript client (task 2) are complete.** The spec is `docs/adapters/spec.md` (Laravel, Symfony, Yii, the TypeScript client; the Univeros module is `univeros/polaris` 2.0 in its own repository, prepared as `docs/adapters/univeros-polaris-2.0.md`); decisions are in `docs/adapters/decisions.md`. Every adapter is proven by the functional suite and the contract fixtures replayed through its own HTTP kernel; the client is generated from the manifest and smoke-tested against the Slim demo.
- **The infrastructure program is complete** (September 2026): the plugin runtime (`Polaris\Contract\Plugin`, `docs/plugins/README.md`) and six packages on it, none part of core: `polaris/audit`, `polaris/admin`, `polaris/messaging`, `polaris/sentinel`, `polaris/sso`, `polaris/scim`, released 0.2.0 to 0.6.0 with their client namespaces; decisions are in `docs/plugins/decisions.md`. Core's 52 routes are unchanged.
- **Program 4 is open** (October 2026, from 0.6.1): `docs/better/spec.md` — ten plugins (`polaris/passwordless`, `polaris/username`, `polaris/anonymous`, `polaris/multi-session`, `polaris/social`, `polaris/passkey`, `polaris/api-keys`, `polaris/oauth-provider`, `polaris/mcp`, `polaris/agents`), two agent SDKs (`packages/agent-ts`, `packages/agent`), `polaris init`/`add`, skills and the Claude Code plugin, in six work packages (spec §8), branch `better/wpN`; decisions go to `docs/better/decisions.md`. WP1 (`polaris/passwordless`, `polaris/username`, `polaris/anonymous`, `polaris/multi-session`) is released as 0.7.0, WP2 (`polaris/social`, `polaris/passkey`, with the one planned core seam, the MFA factor-type registration) as 0.8.0, WP3 (`polaris/api-keys`, `polaris/oauth-provider`, with two more core seams, the bearer resolvers and the delegated authority, decisions #2 and #3) as 0.9.0.

Entry points: `Polaris::create(new Polaris\Wiring\Config(...))` builds the service graph without a container (plugins included, `docs/plugins/README.md`); `Polaris\Psr15\Pipeline` wraps it as PSR-15 middleware plus handler; `bin/polaris` offers `schema:export`, `schema:diff`, `manifest` and `doctor`. The functional suite replays 184 recorded 1.0 fixtures through the pipeline (`packages/core/tests/Contract`), so every response is contract-frozen. Check `docs/extraction/decisions.md` for what has been decided since this file was written.

## The rules

1. **No feature work on core outside a task's spec.** Programs 1–3 are complete; program 4 is `docs/better/spec.md` and its packages add nothing to core beyond what `docs/better/decisions.md` logs (the one planned seam, the MFA factor-type registration of spec §3.2 and §9, landed with WP2 as `Polaris\Contract\MfaFactorType` and `MfaFactorTypeProvider`; WP3 added `Polaris\Contract\BearerResolver` and `BearerResolverProvider`, consulted by the pipeline before the JWT parse, and the `delegated` token metadata `Gate::authority()` intersects with). The plugin runtime (`docs/plugins/README.md`) is the seam every package uses. If a behaviour of the 52 routes must change, log it in `docs/extraction/behaviour-changes.md` first.
2. **`composer qa` (phpcs, phpstan, phpunit) must pass** before any commit is proposed. Do not weaken phpstan level or skip tests to get green.
3. **Nothing in this repository may import** `Altair\`, `Cycle\` or `Univeros\`; framework namespaces (`Illuminate\`, `Symfony\Bundle\`, `Yiisoft\`, ...) only inside their adapter package. Allowed dependencies are listed in each spec's §2.
4. **Public HTTP contract is frozen.** Every request/response shape in `api/**/*.yaml` and `docs/auth/api-reference.md` stays identical. The contract-freeze fixtures (WP6) enforce it.
5. **Namespaces.** Everything is `Polaris\*`. No aliases to `Univeros\Polaris\*`; that namespace belongs to the other repository.
6. **Endpoints are declared in YAML, not in code.** `packages/core/api/**/*.yaml` is the router. Adding or changing an endpoint means editing its spec; the endpoint class only implements it.
7. **Security-critical code.** Password hashing, token minting and rotation, OTP handling, and encryption are not refactored for style. Move them, fix imports, keep their tests.

## How to work a work package

1. Read the task spec's §8 for the WP's scope and acceptance criteria (`docs/better/spec.md` for program 4).
2. Create branch `<program>/wpN` from `main` (`better/wpN` for program 4).
3. Make the smallest change that meets the acceptance criteria; run `composer qa` continuously.
4. Record decisions in the task's `decisions.md`, append only.
5. Open a pull request whose description lists each acceptance criterion with how it was verified.

## Layout

```
packages/core/src/{Contract,Model,Schema,Repository,Identity,Mfa,Token,Authorization,Security,Event,Exception,Config,Support,Http,Wiring}
packages/psr15/src/{RequestHandler.php,Middleware/}
packages/pdo/src   packages/testing/src   packages/cli/src
packages/laravel/src/{PolarisServiceProvider.php,PolarisFactory.php,Auth,Console,Events,Http,Mail,Schema}   the Laravel adapter (task 2 WP1)
packages/symfony/src/{PolarisBundle.php,Factory.php,Event,Http,Mail,Routing,Security}                        the Symfony adapter (task 2 WP2)
packages/yii/{config,src/{Factory.php,Auth,Event,Http,Mail}}                                                 the Yii 3 adapter (task 2 WP3)
packages/audit/{api/audit,src/{AuditPlugin.php,Catalog.php,Recorder.php,Store.php,Sink,Drain,Query,Retention,Activity,Http,Console}}      the audit plugin (polaris/audit), the first package on the plugin runtime
packages/messaging/{src/{MessagingPlugin.php,Sender.php,MessagePolicy.php,Channel,Template,Bridge,Console},resources/translations}   the messaging plugin (polaris/messaging), core's mail and SMS ports over channels and templates
packages/admin/{api/admin,src/{AdminPlugin.php,Principal,Grants.php,Keys.php,Users.php,Impersonation.php,Organizations.php,Stats.php,AdminAudit.php,Http,Console}}   the admin plugin (polaris/admin), the operator API over the audit plugin
packages/sentinel/{api/sentinel,src/{SentinelPlugin.php,Engine.php,Policy.php,Signal,Provider,Http,Console},resources/disposable-domains.txt}   the sentinel plugin (polaris/sentinel), the risk engine in front of the guarded auth routes
packages/sso/{api/sso,src/{SsoPlugin.php,SsoService.php,Provisioner.php,Providers.php,Domains.php,Sp.php,Oidc,Saml,Domain,Http/{Flow,Organization,Admin}}}   the sso plugin (polaris/sso), per-organization SAML and OIDC providers, verified domains, single logout
packages/scim/{api/scim,src/{ScimPlugin.php,Connections.php,Resources.php,Users.php,Groups.php,Filter.php,Patch.php,Http/{ScimMiddleware.php,Resources,Organization,Admin}}}   the scim plugin (polaris/scim), a SCIM 2.0 server per organization over members and roles
packages/passwordless/{api/passwordless,src/{PasswordlessPlugin.php,Settings.php,SecretStore.php,Sessions.php,MagicLinks.php,EmailOtp.php,PhoneSignIn.php,Phones.php,OneTimeTokens.php,Model,Http}}   the passwordless plugin (polaris/passwordless, program 4 WP1): magic links, email and phone codes, one-time tokens
packages/username/{api/username,src/{UsernamePlugin.php,Rules.php,Usernames.php,Model,Http}}   the username plugin (polaris/username, WP1): case-insensitive usernames, sign-in through core's password path
packages/anonymous/{api/anonymous,src/{AnonymousPlugin.php,Guests.php,Model,Http,Console}}   the anonymous plugin (polaris/anonymous, WP1): guest sessions, conversion through onConvert, anonymous:prune
packages/multi-session/{api/multi-session,src/{MultiSessionPlugin.php,Devices.php,Model,Http/{DeviceMiddleware.php,...}}}   the multi-session plugin (polaris/multi-session, WP1): accounts per device, switch, revoke, last method
packages/social/{api/social,src/{SocialPlugin.php,Settings.php,SocialService.php,Providers.php,Accounts.php,Sessions.php,Provider/{Provider.php,Definition.php,Catalog.php,OAuth2Provider.php,AppleProvider.php,GitHubProvider.php,IdTokens.php,Http.php},Event,Model,Http}}   the social plugin (polaris/social, program 4 WP2): OAuth 2.0 / OIDC providers, linking, One Tap, provider tokens, the OAuth proxy
packages/passkey/{api/passkey,src/{PasskeyPlugin.php,Settings.php,PasskeyService.php,Passkeys.php,Sessions.php,Protocol.php,WebauthnProtocol.php,Factor/PasskeyFactorType.php,Model,Http}}   the passkey plugin (polaris/passkey, WP2): WebAuthn registration and sign-in, a passkey as a core MFA factor through the factor-type seam
packages/api-keys/{api/api-keys,src/{ApiKeysPlugin.php,Settings.php,Keys.php,IssuedKey.php,Model,Event,Http/{ApiKeyResolver.php,ApiKeyMiddleware.php,...}}}   the api-keys plugin (polaris/api-keys, program 4 WP3): user and organization keys as principals on every route, through core's bearer-resolver seam
packages/oauth-provider/{api/oauth,src/{OAuthPlugin.php,Settings.php,Jwt.php,Dpop.php,Clients.php,Codes.php,Tokens.php,Consents.php,Authorization.php,Devices.php,Ciba.php,Exchange.php,Discovery.php,OAuthResolver.php,Model,Event,Http/{Organization,Admin,...}}}   the OAuth provider plugin (polaris/oauth-provider, id `oauth`, WP3): OAuth 2.1 / OIDC with PKCE, DPoP, device, CIBA, token exchange, DCR, CIMD; its access tokens are principals on every route
packages/{mcp,agents}/   program 4's other plugins, each `{api/<id>,src,tests}` like the ones above (see docs/better/spec.md §3–4); none exists until its WP lands
packages/agent-ts, packages/agent   the agent SDKs (program 4 WP4): npm @polaris-auth/agent and Composer polaris/agent
skills/<package>/SKILL.md, plugins/claude-code/   the per-package skills and the Claude Code plugin (program 4 WP5)
packages/client-ts/{src/{index.ts,schema.d.ts},test,openapi.json}                                           the TypeScript client (task 2 WP5), npm @polaris-auth/client, not a Composer package
packages/core/api/         endpoint specs, the router (shipped inside polaris/core)
docs/auth/                 identity design (unchanged)
docs/extraction/           task 1 (complete)
docs/adapters/             task 2 (complete)
docs/plugins/              the plugin contract (Polaris\Contract\Plugin) and the decisions of the packages built on it
docs/better/               program 4: spec, decisions, Agent Auth Protocol compatibility notes
examples/                  walkthrough.sh (shared), slim/, laravel/, symfony/, yii/; one demo per adapter
```

## Useful commands

```
composer qa            # cs + stan + test, all packages
composer test          # phpunit
composer stan
composer cs-fix
bin/polaris doctor
bin/polaris manifest   # validate packages/core/api/**/*.yaml, emit OpenAPI
npm --prefix packages/client-ts run generate   # regenerate the TypeScript client from the manifest (checked in, drift-checked in CI)
```

## Namespaces you will see and must not confuse

- `Polaris\` — this repository (new).
- `Univeros\Polaris\` — the 1.0 module's namespace; it belongs to the other repository and appears nowhere here.
- `Altair\*` — the Univeros framework's packages. Gone since WP7; `bin/check-imports` fails on any reference. Never add one.
