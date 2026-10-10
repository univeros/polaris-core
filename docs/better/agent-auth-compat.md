# The Polaris agent protocol, and Better Auth's Agent Auth Protocol

`polaris/agents` serves the protocol this file defines. It is compatible with the subset of Better Auth's
Agent Auth Protocol (`@better-auth/agent-auth`, specification `1.0-draft` at agentauthprotocol.com) listed
under "The compatible subset": an agent written against that protocol can discover Polaris, call a
capability with a signed JWT and read the errors, without a compatibility switch, because Polaris only
adds fields. Spec §9.6 and `decisions.md` (2026-10-10, WP4) record why it is a Polaris document rather
than exact compatibility. Update this file when either side moves, and date the change.

- 2026-10-10: first normative version (WP4), against AAP `1.0-draft`.

## Discovery

`GET <mount>/.well-known/agent-configuration`, public, `Cache-Control: public, max-age=3600`. It is a route
under the Polaris mount, as the OAuth documents are; serving it at the application root is the host's
alias. Endpoints are absolute URLs.

| Field | AAP | Polaris |
| --- | --- | --- |
| `version` | `1.0-draft` | same |
| `provider_name`, `description` | required | the plugin's `providerName` and `description` |
| `issuer` | base URL | core's issuer |
| `default_location` | `endpoints.execute` | same |
| `algorithms` | `["Ed25519"]` | `["EdDSA", "ES256"]` (JOSE names) |
| `modes` | `delegated`, `autonomous` | same |
| `approval_methods` | `device_authorization`, `ciba` | same plus `in_app` |
| `endpoints` | `register`, `capabilities`, `execute`, `request_capability`, `status`, `revoke`, ... | `register`, `enroll`, `capabilities`, `execute`, `request_capability`, `status` (the session), `revoke`, `grants`, `approvals`, `receipts`, `mcp` (when `polaris/mcp` is registered), `token` |
| `approval_strengths` | — | risk tier → `session`, `step_up` or `passkey` |
| `token_endpoint` | — | the OAuth token endpoint (`/oauth2/token`) |
| `agent_sdk_versions` | — | `{"@polaris-auth/agent": "<version>", "polaris/agent": "<version>"}`, informative |

The document validates against this schema (the WP4 test reads it from this file):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["version", "provider_name", "description", "issuer", "default_location", "algorithms", "modes", "approval_methods", "approval_strengths", "endpoints", "token_endpoint"],
  "properties": {
    "version": {"const": "1.0-draft"},
    "provider_name": {"type": "string", "minLength": 1},
    "description": {"type": "string"},
    "issuer": {"type": "string", "format": "uri"},
    "default_location": {"type": "string", "format": "uri"},
    "algorithms": {"type": "array", "items": {"enum": ["EdDSA", "ES256"]}, "minItems": 1},
    "modes": {"type": "array", "items": {"enum": ["delegated", "autonomous"]}, "minItems": 1},
    "approval_methods": {"type": "array", "items": {"enum": ["device_authorization", "ciba", "in_app"]}, "minItems": 1},
    "approval_strengths": {
      "type": "object",
      "required": ["low", "medium", "high"],
      "additionalProperties": false,
      "patternProperties": {"^(low|medium|high)$": {"enum": ["session", "step_up", "passkey"]}}
    },
    "endpoints": {
      "type": "object",
      "required": ["register", "enroll", "capabilities", "execute", "request_capability", "status", "revoke", "grants", "approvals", "receipts", "token"],
      "additionalProperties": {"type": "string", "format": "uri"}
    },
    "token_endpoint": {"type": "string", "format": "uri"},
    "agent_sdk_versions": {"type": "object", "additionalProperties": {"type": "string"}}
  }
}
```

`default_location` equals `endpoints.execute`. Unknown fields are ignored by both sides.

## Capabilities

Declared in the plugin's configuration: `name`, `description`, `input` (JSON Schema), `permission` (a
permission name the owner must hold), `risk` (`low|medium|high`), optional `location` (a host URL) or a
`handler` (run by `POST /agents/execute`). `GET /agents/capabilities` answers
`{data: {capabilities: [...], next_cursor: null, has_more: false}}`; each capability carries AAP's `name`,
`description`, `input`, `location` (when set) plus `permission` and `risk`, and `grant_status`
(`active|pending|none`) when an agent asks.

## Agent authentication

Three ways (spec §4.3), all answered with the agent as the actor:

1. **Client credentials** at `/oauth2/token` (`client_secret_basic` or a `private_key_jwt` assertion) for
   an autonomous agent: the agent's id is its OAuth `client_id`, so the token's `sub` is the agent.
2. **Token exchange** (RFC 8693) for a delegated agent: the agent's client exchanges the user's access
   token; the token's `sub` is the user and `act` is `{sub: <agent>, client_id: <agent>}`.
3. **Signed request JWTs** (AAP compatible), sent as `Authorization: Bearer <jwt>`:

| Claim / header | Rule |
| --- | --- |
| header `typ` | `agent+jwt` |
| header `alg` | `ES256` or `EdDSA`; the agent's registered key verifies it (no `jku`, `x5u` or `jwk` header) |
| `sub` | the agent's id |
| `aud` | the exact URL called: scheme, host, port, path, no query |
| `iat`, `exp` | `exp - iat` ≤ 300 seconds, 60 seconds of clock leeway |
| `jti` | once per agent until `exp` |
| `capabilities` | optional; restricts the grants the JWT may use |
| `htm`, `htu`, `body_hash` | optional Polaris request binding (AAP defines none): the method, the URL, base64url SHA-256 of the raw body; checked when present |

AAP's `iss` (the host's key thumbprint) is not required. A JWT that lists several capabilities cannot use
their `location` values as `aud`; it is refused with `agents/aud_mismatch`.

## Execution

`POST /agents/execute` with `{capability, arguments}` (AAP's names; `input` is accepted as an alias)
answers `200 {data: <the handler's result>, receipt: {id, hash}}`. A capability with a `location` is
executed by calling the location, through `AgentRequestMiddleware`, with the same checks: grant,
constraints, budget, receipt. Errors are RFC 9457 problem documents whose `error` member carries AAP's
code where one exists:

| Polaris problem type | `error` | Status |
| --- | --- | --- |
| `agents/invalid_jwt` | `invalid_jwt` | 401 |
| `agents/aud_mismatch` | `aud_mismatch` | 401 |
| `agents/agent_inactive` | `agent_revoked` or `agent_suspended` | 401 |
| `agents/capability_not_found` | `capability_not_found` | 404 |
| `agents/capability_not_granted` | `capability_not_granted` | 403 |
| `agents/constraint_violated` | `constraint_violated` (with `violations: [{field, constraint, actual}]`) | 403 |
| `agents/budget_exhausted` | `budget_exhausted` | 403 |

## Grants and approvals

`POST /agents/grants/request` (the agent) with `{capabilities: [name | {name, constraints}], reason?,
preferred_method?, binding_message?}` answers AAP's `{agent_id, agent_capability_grants, approval?}`; the
approval carries `id`, `method`, `user_code`, `verification_uri`, `verification_uri_complete`,
`expires_in`, `interval`. Grant `status` is `active`, `pending`, `denied`, `revoked` or `exhausted`.
Constraints use AAP's operators per argument (`max`, `min`, `in`, `not_in`) plus `pattern`, and
`budget: {count | amount, window?}`; an unknown operator is `400 agents/unknown_constraint_operator`.

The owner finds a `device_authorization` approval by its user code at
`GET /agents/approvals/code?user_code=` (the data of the host's device page), lists `in_app` ones at
`GET /agents/approvals`, and decides any of them at `POST /agents/approvals/{id}/decide`.

## Sessions and hosts

AAP's `GET /agent/status` is Polaris's `GET /agents/session` (the agent, its mode and owner, its grants with
remaining budgets, its host). A host (a runtime that enrols agents) is created by its owner and receives an
enrolment token (`peh_...`, shown once, stored as a keyed hash); `POST /agents/enroll` with it as the bearer
creates an agent under the host's default capabilities. Every enrolment is an audited event.

## The compatible subset

An AAP `1.0-draft` agent can rely on: the discovery fields of the first table; the capability object; the
agent JWT as above (sent as a bearer, `typ: agent+jwt`, `aud`, `jti`, `exp`, `capabilities`); the execute
request and its synchronous `{data}` answer; the error codes above in `error`. Polaris does not serve AAP's
host JWTs (`host+jwt`) or its registration by host JWT (a host enrols with its enrolment token), key
rotation, reactivation, introspection by agent, asynchronous or streamed execution, or Better Auth's
OpenAPI capability adapter.

## What Polaris adds

Delegation by RFC 8693 token exchange (`act` through the whole stack, core's RBAC and the delegation rule
applied to every agent token), budgets decremented in the execution transaction, `in_app` approval and
auto-approval by risk tier, signed receipt chains with `verify`, the kill switch (`revoke` ends tokens,
grants and approvals and seals the chain), operator routes under `/admin/agents`, and every capability as
an MCP tool on `/mcp` with the same execution path.
