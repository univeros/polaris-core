# `polaris/agents` and Better Auth's Agent Auth Protocol

Better Auth ships `@better-auth/agent-auth`, which it describes as an implementation of a standard under
heavy development and not yet stable. `polaris/agents` keeps the shapes that are defined so an agent
built against that protocol can enrol with Polaris, and is stricter where the protocol is silent. This
file is the mapping WP4 is held to; update it when the protocol moves (date each change).

## Discovery

`GET /.well-known/agent-configuration` at the application root (the adapters register it outside the
API prefix, like `/.well-known/openid-configuration`).

| Field | Better Auth | Polaris |
| --- | --- | --- |
| `issuer` | base URL | same |
| `endpoints.*` | absolute URLs; `execute` is `POST /capability/execute` | same keys, Polaris paths; `execute` is `POST /agents/execute`; adds `register`, `enroll`, `grants`, `approvals`, `receipts`, `mcp`, `token` |
| `default_location` | equals `endpoints.execute`; the `aud` for capabilities without `location` | same rule |
| `modes` | `delegated`, `autonomous` | same |
| `approval_methods` | `device_authorization`, `ciba` | same two plus `in_app` |
| `approval_strength` | configurable (e.g. WebAuthn) | published as `approval_strengths: session|step_up|passkey` per risk tier |
| `agent_sdk_versions` | — | Polaris addition, informative |

Unknown fields are ignored by both sides; Polaris never removes a field Better Auth defines.

## Capabilities

Better Auth: `GET /capability/list` → name, description, JSON-Schema `input`, optional `location`.
Polaris: `GET /agents/capabilities` → the same fields plus `permission` and `risk`. Capabilities with a
`location` are reachable only through `AgentRequestMiddleware` (Better Auth skips its `onExecute` for
them and leaves constraint checks to the app; Polaris does not).

## Request signing

Both: the agent signs a short-lived JWT, `aud` = the exact URL called, `jti` replay-checked, `exp`
short, optional request-binding claims. Polaris fixes `exp` ≤ 5 minutes, binds `htm`/`htu` and the
body hash when present, and accepts the agent's registered JWK only (no `jku`). A JWT listing several
capabilities cannot use per-capability `location` values as `aud` in either implementation; Polaris
refuses such a token with `agents/aud_mismatch`.

## Grants and approvals

Both store grants and intersect active grants with the JWT's `capabilities` claim at execution. Polaris
adds `constraints.budget` (count or amount per window, decremented in the execution transaction),
`in_app` approval, auto-approval policy by risk tier, and a receipt per execution. Better Auth's
`approvalStrength` becomes Polaris's per-tier `approval_strengths`.

## Sessions

Better Auth: `GET /agent/session`. Polaris: `GET /agents/session` with the same core fields (agent,
mode, owner, grants) plus remaining budgets and the host.

## Hosts

Both have hosts that enrol agents under a default capability policy; Polaris enrolment is by a hashed
enrolment token the host owner creates and rotates, and every enrolment is an auditable event.

## What Polaris adds that has no counterpart

Delegation by RFC 8693 token exchange (`act` claims through the whole stack), signed receipt chains with
`verify`, the kill switch (`revoke` ends tokens, grants, approvals and seals the chain), operator routes
under `/admin/agents`, and every capability as an MCP tool on `/mcp` with the same execution path.

## What Polaris does not implement

Better Auth's OpenAPI adapter (capabilities derived from an OpenAPI 3.x spec with a proxy `onExecute`)
is out of scope for WP4; it is a natural later addition since Polaris already owns an OpenAPI document.
