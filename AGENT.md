# AGENT.md — univeros/polaris-core (Polaris for PHP)

Orientation for coding agents working in this repository. Read this before editing. The identity design lives in `docs/auth/`; the current engineering task lives in `docs/extraction/`.

This repository (`github.com/univeros/polaris-core`) publishes the `polaris/*` Composer packages. It was seeded from `univeros/polaris` v1.0.0. **`univeros/polaris` is a different repository and must never be modified from here.** It remains the Univeros module for Univeros hosts; this repository is the framework-agnostic Polaris for PHP.

## Status

- **The code is the complete Polaris 1.0.0** (June 2026): authentication, MFA/OTP, sessions and rotating refresh tokens, multi-tenant organizations and RBAC, audit log, 35 PSR-14 events, 52 endpoints specified in `api/**/*.yaml`, 115 test files.
- **Extraction (task 1) is done through WP7.** The monorepo holds `packages/core` (`Polaris\`, framework-free), `packages/psr15`, `packages/pdo`, `packages/testing`, `packages/cli`; nothing imports `Altair\`, `Cycle\` or `Univeros\` any more (`bin/check-imports` blocks it). The authoritative spec is `docs/extraction/spec.md`; the decisions taken along the way are in `docs/extraction/decisions.md`, the one behaviour change in `behaviour-changes.md`. WP8 (the Slim demo) is the remaining work package.

Entry points: `Polaris::create(new Polaris\Wiring\Config(...))` builds the service graph without a container; `Polaris\Psr15\Pipeline` wraps it as PSR-15 middleware plus handler; `bin/polaris` offers `schema:export`, `schema:diff`, `manifest` and `doctor`. The functional suite replays 184 recorded 1.0 fixtures through the pipeline (`packages/core/tests/Contract`), so every response is contract-frozen. Check `docs/extraction/decisions.md` for what has been decided since this file was written.

## The rules

1. **No feature work during extraction.** Only what `docs/extraction/spec.md` describes. If a behaviour must change, log it in `docs/extraction/behaviour-changes.md` first.
2. **`composer qa` (phpcs, phpstan, phpunit) must pass** before any commit is proposed. Do not weaken phpstan level or skip tests to get green.
3. **Nothing in this repository may import** `Altair\`, `Cycle\`, `Univeros\`, or any framework namespace once WP7 is done. Allowed dependencies are listed in `spec.md` §2.
4. **Public HTTP contract is frozen.** Every request/response shape in `api/**/*.yaml` and `docs/auth/api-reference.md` stays identical. The contract-freeze fixtures (WP6) enforce it.
5. **Namespaces.** Everything is `Polaris\*`. No aliases to `Univeros\Polaris\*`; that namespace belongs to the other repository.
6. **Endpoints are declared in YAML, not in code.** After WP5, `api/**/*.yaml` is the router. Adding or changing an endpoint means editing its spec; the endpoint class only implements it.
7. **Security-critical code.** Password hashing, token minting and rotation, OTP handling, and encryption are not refactored for style. Move them, fix imports, keep their tests.

## How to work a work package

1. Read `docs/extraction/spec.md` §8 for the WP's scope and acceptance criteria, and `coupling-analysis.md` for the directories involved.
2. Create branch `extract/wpN` from `main`.
3. Make the smallest change that meets the acceptance criteria; run `composer qa` continuously.
4. Record decisions in `docs/extraction/decisions.md`.
5. Open a pull request whose description lists each acceptance criterion with how it was verified.

## Layout after WP1

```
packages/core/src/{Contract,Model,Schema,Repository,Identity,Mfa,Token,Authorization,Security,Event,Exception,Config,Support,Http,Wiring}
packages/psr15/src/{RequestHandler.php,Middleware/}
packages/pdo/src   packages/testing/src   packages/cli/src
api/                       endpoint specs (router after WP5)
docs/auth/                 identity design (unchanged)
docs/extraction/           this task
examples/slim/             WP8 demo
```

## Useful commands

```
composer qa            # cs + stan + test, all packages
composer test          # phpunit
composer stan
composer cs-fix
bin/polaris doctor     # after WP7
bin/polaris manifest   # after WP7: validate api/*.yaml, emit OpenAPI
```

## Namespaces you will see and must not confuse

- `Polaris\` — this repository (new).
- `Univeros\Polaris\` — the 1.0 module's namespace; it belongs to the other repository and appears nowhere here.
- `Altair\*` — the Univeros framework's packages. Gone since WP7; `bin/check-imports` fails on any reference. Never add one.
