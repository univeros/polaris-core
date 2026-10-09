# Program 4 — "Better Auth for PHP"

Programs 1 to 3 made Polaris for PHP framework-agnostic (`docs/extraction`), gave it four hosts and a
TypeScript client (`docs/adapters`), and built the infrastructure tier on the plugin runtime
(`docs/plugins`). This program closes the gap to Better Auth on sign-in methods and OAuth/MCP, adds the
agent-native layer Better Auth does not have, and makes the whole thing installable and operable by an
AI coding agent. It starts from 0.6.1.

- [`spec.md`](spec.md) — positioning and the migration map (§1), the claims the site will make (§2),
  the ten packages (§3, §4), client and host surface (§5), the agent-accessible developer surface (§6),
  the work packages with their acceptance criteria (§8), and what is decided by default (§9).
- [`decisions.md`](decisions.md) — the append-only log; one entry per decision taken while working a WP.
- [`agent-auth-compat.md`](agent-auth-compat.md) — how `polaris/agents` maps to Better Auth's Agent Auth
  Protocol shapes, so WP4 has something concrete to be compatible with.

Order: WP1 passwordless/username/anonymous/multi-session (0.7.0) → WP2 social/passkey (0.8.0) → WP3
api-keys/oauth-provider (0.9.0) → WP4 mcp/agents + SDKs (0.10.0) → WP5 developer surface (0.11.0) →
WP6 1.0.0. One WP per release, one pull request per WP, branch `better/wpN`.

Not in this program: billing (Better Auth's six payment plugins), Sign In With Ethereum, Polaris Cloud.
