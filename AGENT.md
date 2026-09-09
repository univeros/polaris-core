# AGENT.md — univeros/polaris-core (Polaris for PHP)

Orientation for coding agents working in this repository. Read this before editing. The identity design lives in `docs/auth/`; the current engineering task lives in `docs/extraction/`.

This repository (`github.com/univeros/polaris-core`) publishes the `polaris/*` Composer packages. It was seeded from `univeros/polaris` v1.0.0. **`univeros/polaris` is a different repository and must never be modified from here.** It remains the Univeros module for Univeros hosts; this repository is the framework-agnostic Polaris for PHP.

## Status

- **The code is the complete Polaris 1.0.0** (June 2026): authentication, MFA/OTP, sessions and rotating refresh tokens, multi-tenant organizations and RBAC, audit log, 35 PSR-14 events, 52 endpoints specified in `api/**/*.yaml`, 115 test files.
- **Current task: extraction.** This repository is being restructured into a monorepo so the same code runs in any PHP application: `packages/core` (`Polaris\`, framework-free), `packages/psr15`, `packages/pdo`, `packages/testing`, `packages/cli`. Everything Univeros-specific (`Module.php`, `Bootstrap/*`, Cycle entities and repositories, the Altair HTTP layer) is replaced, not adapted. The authoritative spec is `docs/extraction/spec.md`; work packages WP0–WP8 are executed in order on branches `extract/wpN`.

Until WP1 lands, code still lives under `src/` with the 1.0 layout. Check `docs/extraction/decisions.md` for what has been decided since this file was written.

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
- `Univeros\Polaris\` — the seeded 1.0 code, present until each layer is moved; gone by WP7.
- `Altair\*` — the Univeros framework's packages (`univeros/http`, `univeros/persistence`, …). Present in the seed; every import is removed by WP7. Never add one.
