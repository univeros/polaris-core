# AGENT.md — univeros/polaris-core (Polaris for PHP)

Orientation for coding agents working in this repository. Read this before editing. The identity design lives in `docs/auth/`; task 1 (the extraction, complete) lives in `docs/extraction/`, task 2 (the framework adapters, in progress) in `docs/adapters/`.

This repository (`github.com/univeros/polaris-core`) publishes the `polaris/*` Composer packages. It was seeded from `univeros/polaris` v1.0.0. **`univeros/polaris` is a different repository and must never be modified from here.** It remains the Univeros module for Univeros hosts; this repository is the framework-agnostic Polaris for PHP.

## Status

- **The code is the complete Polaris 1.0.0** (June 2026): authentication, MFA/OTP, sessions and rotating refresh tokens, multi-tenant organizations and RBAC, audit log, 35 PSR-14 events, 52 endpoints specified in `packages/core/api/**/*.yaml`, 115 test files.
- **Extraction (task 1) is complete.** The monorepo holds `packages/core` (`Polaris\`, framework-free), `packages/psr15`, `packages/pdo`, `packages/testing`, `packages/cli`; nothing imports `Altair\`, `Cycle\` or `Univeros\` any more (`bin/check-imports` blocks it). The spec was `docs/extraction/spec.md`; the decisions taken along the way are in `docs/extraction/decisions.md`, the one behaviour change in `behaviour-changes.md`; the Slim demo is `examples/slim`.
- **Framework adapters and the TypeScript client (task 2) are complete.** The spec is `docs/adapters/spec.md` (Laravel, Symfony, Yii, the TypeScript client; the Univeros module is `univeros/polaris` 2.0 in its own repository, prepared as `docs/adapters/univeros-polaris-2.0.md`); decisions are in `docs/adapters/decisions.md`. Every adapter is proven by the functional suite and the contract fixtures replayed through its own HTTP kernel; the client is generated from the manifest and smoke-tested against the Slim demo.

Entry points: `Polaris::create(new Polaris\Wiring\Config(...))` builds the service graph without a container (plugins included, `docs/plugins/README.md`); `Polaris\Psr15\Pipeline` wraps it as PSR-15 middleware plus handler; `bin/polaris` offers `schema:export`, `schema:diff`, `manifest` and `doctor`. The functional suite replays 184 recorded 1.0 fixtures through the pipeline (`packages/core/tests/Contract`), so every response is contract-frozen. Check `docs/extraction/decisions.md` for what has been decided since this file was written.

## The rules

1. **No feature work on core outside a task's spec.** Task 2 (`docs/adapters/spec.md`) is complete; the plugin runtime (`docs/plugins/README.md`) is the seam the packages built on it use, and those packages add nothing to core beyond what `docs/plugins/decisions.md` logs. If a behaviour of the 52 routes must change, log it in `docs/extraction/behaviour-changes.md` first.
2. **`composer qa` (phpcs, phpstan, phpunit) must pass** before any commit is proposed. Do not weaken phpstan level or skip tests to get green.
3. **Nothing in this repository may import** `Altair\`, `Cycle\` or `Univeros\`; framework namespaces (`Illuminate\`, `Symfony\Bundle\`, `Yiisoft\`, ...) only inside their adapter package. Allowed dependencies are listed in each spec's §2.
4. **Public HTTP contract is frozen.** Every request/response shape in `api/**/*.yaml` and `docs/auth/api-reference.md` stays identical. The contract-freeze fixtures (WP6) enforce it.
5. **Namespaces.** Everything is `Polaris\*`. No aliases to `Univeros\Polaris\*`; that namespace belongs to the other repository.
6. **Endpoints are declared in YAML, not in code.** `packages/core/api/**/*.yaml` is the router. Adding or changing an endpoint means editing its spec; the endpoint class only implements it.
7. **Security-critical code.** Password hashing, token minting and rotation, OTP handling, and encryption are not refactored for style. Move them, fix imports, keep their tests.

## How to work a work package

1. Read the task spec's §8 for the WP's scope and acceptance criteria (`docs/adapters/spec.md` for task 2).
2. Create branch `adapters/wpN` from `main`.
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
packages/client-ts/{src/{index.ts,schema.d.ts},test,openapi.json}                                           the TypeScript client (task 2 WP5), npm @polaris-auth/client, not a Composer package
packages/core/api/         endpoint specs, the router (shipped inside polaris/core)
docs/auth/                 identity design (unchanged)
docs/extraction/           task 1 (complete)
docs/adapters/             task 2 (complete)
docs/plugins/              the plugin contract (Polaris\Contract\Plugin) and the decisions of the packages built on it
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
