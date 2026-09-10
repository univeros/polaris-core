# Framework adapters — working folder (task 2)

Everything needed to run task 2 (the Laravel, Symfony and Yii adapters and the TypeScript client) lives here. Task 1, the extraction, is documented in `../extraction/` and is complete.

| File | Read when |
|---|---|
| `spec.md` | Before starting any work package. The authoritative spec: ground rules, target layout, dependency rules, the adapter contract (boot, routes, auth, schema, mail, console, the functional proof, the demo), one section per adapter, WP0–WP4 with acceptance criteria, definition of done. |
| `decisions.md` | Whenever a choice is made that the spec left open. Append, never rewrite. |
| `../extraction/target-design.md` | For adapter conventions and the plugin contract (the plugin contract is task 3). |
| `../extraction/behaviour-changes.md` | The single register of observable changes; an adapter never adds one on its own, only a decisions-logged core fix can. |

Working rules (from `spec.md` §0): no feature work on core; every adapter is proven by the functional suite plus the 184 contract fixtures through its own HTTP kernel; framework namespaces only in their package (`bin/check-imports`); PHP 8.3 stays the floor.

Branches: `adapters/wp1` … `adapters/wp4`, one at a time, each merged before the next starts.

## Status (2026-09-10)

WP0 (preparation) is done: the split workflow, the per-package READMEs and the manifest inside `polaris/core` (PR #12), this folder (PR #13). WP1 (Laravel), WP2 (Symfony) and WP3 (Yii) are done: `packages/{laravel,symfony,yii}` with `examples/{laravel,symfony,yii}`; the functional suite and the 184 fixtures replay through each framework's kernel in CI, each demo runs the shared walkthrough. WP4 (the TypeScript client) is next.
