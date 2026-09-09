# Kickoff prompt for Claude Code (paste as the first message in ~/projects/polaris-core)

This repository is github.com/univeros/polaris-core, the new Polaris for PHP monorepo that publishes the polaris/* Composer packages. It is seeded from a copy of univeros/polaris v1.0.0, which lives separately in ~/projects/polaris and must never be modified from here. Read AGENT.md, then docs/extraction/README.md, spec.md, and coupling-analysis.md in full before doing anything.

Start with WP0 on branch extract/wp0:
1. Confirm the seed: this folder is a git clone of univeros/polaris at tag v1.0.0 with history, origin re-pointed to the new remote. If it is not yet a clone, stop and tell me; do not copy files by hand.
2. Root composer.json: name polaris/monorepo (the root is never published), description "Polaris for PHP: self-hosted authentication, MFA, organizations and RBAC for any PHP application", license MIT. Do not change dependencies yet.
3. Make sure AGENT.md and docs/extraction/* from this drop are in place.
4. Run composer qa and report the result; it must be green before the PR.
5. Open the PR with the WP0 acceptance criteria from spec.md section 8 checked off.

Then stop and wait for review. Do not begin WP1 in the same session.

Rules for every session: no feature work; composer qa green before proposing a commit; never add an import of Altair\, Cycle\, or Univeros\ and remove them as the spec directs; every decision the spec left open goes into docs/extraction/decisions.md; if you are unsure whether something is in scope, it is not.
