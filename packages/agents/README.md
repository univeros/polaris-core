# polaris/agents

AI agents as principals of [Polaris for PHP](https://github.com/univeros/polaris-core): registered by
their owners or enrolled by hosts, each an OAuth client of `polaris/oauth-provider` (client credentials
for an autonomous agent, token exchange with `act` for a delegated one; `private_key_jwt`, a secret or
the user's own token), signed request JWTs, capability grants with constraints and budgets approved by
a person or by policy, one execution path with a signed receipt chain, and a kill switch. Every
capability is an MCP tool when `polaris/mcp` is registered. The protocol is
[`docs/better/agent-auth-compat.md`](../../docs/better/agent-auth-compat.md): what Polaris serves, and
the subset of Better Auth's Agent Auth Protocol an agent can rely on without a compatibility switch.

```sh
composer require polaris/agents
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Capability;
use Polaris\Agents\ExecutionContext;
use Polaris\Audit\AuditPlugin;
use Polaris\OAuth\OAuthPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new AdminPlugin(),
    new OAuthPlugin(baseUrl: 'https://app.example.com/auth'),
    new AgentsPlugin(
        baseUrl: 'https://app.example.com/auth',
        approvalUrl: 'https://app.example.com/agents/approve',
        capabilities: [
            new Capability(
                name: 'deploy.staging',
                description: 'Deploy a build to staging',
                input: ['type' => 'object', 'properties' => ['build' => ['type' => 'string']], 'required' => ['build']],
                permission: 'deploy.staging',
                risk: 'low',
                handler: fn(array $arguments, ExecutionContext $context) => $deployer->deploy($arguments['build']),
            ),
            ['name' => 'billing.refund', 'description' => 'Refund an order', 'input' => [...], 'permission' => 'billing.refund', 'risk' => 'high', 'location' => 'https://app.example.com/api/refunds'],
        ],
    ),
]));
```

`polaris/audit`, `polaris/admin` and `polaris/oauth-provider` are required and must be registered first:
every agent event is an `agent.*` record in the audit store, `/admin/agents` runs on the admin
plugin's principals, and an agent *is* an OAuth client. `baseUrl` is where Polaris is mounted, prefix
included: the discovery document's endpoints derive from it. In Laravel, Symfony and Yii the instance
goes in the adapter's `plugins` configuration; the five tables join `polaris:install`, `schema:create`
and `schema:diff`, the routes join the route table.

## Agents, hosts and capabilities

An **agent** (`polaris_agent`) belongs to a user or to an organization (through the member who
registered it), acts *for* its owner (`delegated`) or *as* its owner (`autonomous`), and authenticates
with a key (`private_key_jwt`: an EC P-256 or Ed25519 public JWK), a secret (`client_secret`, a `pcs_`
secret shown once) or the user's own token (`delegated_token`, for the exchange only). Its id is the
`client_id` of the OAuth client the plugin registers for it: an autonomous agent's client may use
`client_credentials`, a delegated agent's the token exchange; the client's scopes follow the agent's
live grants, so a token is never minted beyond what was granted.

A **host** (`polaris_agent_host`) is a runtime that enrols agents (a Claude Code install, a worker): its
owner creates it (`POST /agents/hosts`) and gets an enrolment token (`peh_...`, shown once, stored as a
keyed hash); `POST /agents/enroll` with it as the bearer creates an agent under the host's owner and
asks for the host's `default_capabilities` at once.

A **capability** is declared in the configuration: `name`, `description`, `input` (a JSON Schema of
the arguments), `permission` (a catalog name the owner must hold; the plugin contributes the ones core
lacks), `risk` (`low`, `medium`, `high`) and exactly one of a `handler` (run by `POST /agents/execute`
and the MCP tool) or a `location` (a host URL guarded by `AgentRequestMiddleware`). `GET
/agents/capabilities` lists them (with `grant_status` when an agent asks); `GET
/.well-known/agent-configuration` is the discovery document.

## The three ways an agent authenticates

1. **Client credentials** at `/oauth2/token` (`client_secret_basic`, or a `private_key_jwt` assertion
   signed with the agent's key and its `kid`) for an autonomous agent: the token's `sub` is the agent.
   On every Polaris route the plugin's middleware makes it act as its owner (a user's agent as the user,
   an organization's as the member who registered it, in that organization), with the permissions of its
   live grants as the delegated authority, and `actor_type: agent`, `agent_id`, `act` in the token.
2. **Token exchange** (RFC 8693) for a delegated agent: its client exchanges the user's access token
   (`subject_token`) for one whose `sub` is the user and `act` is `{sub: <agent>, client_id: <agent>}`,
   within the user's permissions *and* the agent's grants; core's RBAC, the delegation rule (no
   permissionless write, no step-up route), the audit log and the admin plugin all see the user and the
   agent. A grant revoked takes effect at the next request, not at the token's expiry. Only the user the
   agent acts for can be the subject: the token endpoint exchanges any session, so a token naming an
   agent's client whose `sub` is anyone else (a `delegated_token` agent's client is public) is refused
   on every route, `401 agents/invalid_jwt`.
3. **Signed request JWTs** on the agent-facing routes (`POST /agents/execute`, `/agents/grants/request`,
   `GET /agents/session`, `GET /agents/capabilities`) and at capability locations, sent as `Authorization:
   Bearer <jwt>`: header `typ: agent+jwt`, `alg` `ES256` or `EdDSA`, verified with the agent's registered
   key only (no `jku`, `x5u` or `jwk` header), `sub` = the agent, `aud` = the exact URL called (scheme,
   host, port, path; no query), `iat` and `exp` at most `requestJwtMaxAge` (300 s) apart with 60 s of
   leeway, `jti` used once until `exp`, optional `htm`, `htu` and `body_hash` (base64url SHA-256 of the
   raw body) checked when present, optional `capabilities` restricting the grants the JWT may use. A JWT
   listing several capabilities cannot use a location as its `aud` (`agents/aud_mismatch`).

The agent-facing routes are `auth: public` and authenticate the agent themselves, so core's delegation
rule never applies to them; the owner-facing routes are `auth: bearer` self-service writes, so no
delegated credential (a key, a token, an agent) can register an agent or approve a grant. An
organization's agents need `org.update` in the caller's active organization, checked by the endpoint.

## Grants, approvals and strengths

`POST /agents/grants/request` (the agent) names capabilities, each a name or `{name, constraints}`:
AAP's operators per argument (`max`, `min`, `in`, `not_in`) plus `pattern`, and `budget` (`{count: N}`
or `{amount: N, field: argument}`, with an optional `window` in seconds that becomes the grant's
lifetime); an unknown operator is `400 agents/unknown_constraint_operator`. The answer is AAP's
`{agent_id, agent_capability_grants, approval?}`.

What the policy auto-approves is active at once: `autoApprove` (default `['low' => ['count' => 100]]`)
maps a risk tier to the budget it gets (or `true` for none) and applies when the owner holds the
capability's permission and the asked budget, if any, stays within the policy's (the same kind and
field, no larger, and no longer a window when the policy sets one): the policy's budget is a ceiling
the asker cannot raise. The rest waits in one **approval** (`polaris_agent_approval`), whose `method`
only changes how the owner finds it: `device_authorization` (the agent shows the `user_code`; the owner
types it on the host's `approvalUrl` page, which loads `GET /agents/approvals/code?user_code=`), `ciba`
(the host pushes the `binding_message` from the `agent.grant.requested` event, through
`polaris/messaging` for instance) or `in_app` (the owner's own client lists `GET /agents/approvals`).
All decide at `POST /agents/approvals/{id}/decide` with `{decision: approve|deny, constraints?}`, once:
approving needs a session of the **strength** the riskiest capability requires (`strengths`, default
`low` and `medium` `session`, `high` `step_up`: core's step-up freshness; `passkey`: a recent passkey
sign-in) and the owner must hold every permission at that moment. `DELETE /agents/grants/{id}` revokes
a grant; `GET /agents/session` shows the agent its grants and remaining budgets while it waits. Asking
again for a capability that already waits answers the same pending grant and its open approval (a new
one once that approval expired); an approval past `approvalTtl` reads as `expired`; an agent may have at
most five approvals waiting (`409 agents/conflict` beyond that, until one is decided or expires).

## Execution, budgets and receipts

One path for `POST /agents/execute {capability, arguments}` (`input` is an alias), the capability
locations and the MCP tools: the grant must be live, named by the JWT's `capabilities` when it
restricts them and carried as a permission by an access token's scopes; the owner must still hold the
permission; the arguments must match the capability's schema and the grant's constraints
(`403 agents/constraint_violated` with `violations: [{field, constraint, actual}]`). Then, in one
transaction, the budget is spent by a conditional update (`budget_remaining >= cost`; one per call for a
count, the rounded-up value of the budget's argument for an amount), the handler runs and a receipt is
appended. A budget that cannot cover the call is `403 agents/budget_exhausted`; a grant that reaches
zero is `exhausted` (an `agent.grant.exhausted` event) and a refill is a new request. The answer is
`200 {data: <the handler's result>, receipt: {id, seq, hash}}`.

**Receipts** (`polaris_agent_receipt`) form a chain per agent: `seq`, `prev_hash`, `hash` (SHA-256 over
the canonical JSON — sorted keys, unescaped slashes — of `id`, `agent_id`, `seq`, `grant_id`,
`capability`, `input_hash`, `outcome`, `budget_before`, `budget_after`, `prev_hash`, `created_at`) and
`signature`, a compact JWS (`typ: receipt+jwt`, claims `receipt_hash`, `receipt_id`, `agent_id`, `seq`)
signed with core's key and `kid`, verifiable with `/auth/.well-known/jwks.json`. Inputs are stored as a
hash only. `GET /agents/{id}/receipts` exports the chain (`after`, `limit`); `GET
/agents/receipts/{id}/verify` recomputes the hash, verifies the signature and checks the link to the
previous receipt (`{valid, checks: {hash, signature, chain}}`); a receipt changed in the database fails
its own check, and the next one's chain check.

## The kill switch

`POST /agents/{id}/revoke` (the owner) and `POST /admin/agents/{id}/revoke` (an operator with `own`),
in one transaction: the agent is `revoked`, its OAuth client disabled and every token of it revoked, its
grants revoked, its pending approvals cancelled, and a final receipt with the outcome `sealed` closes
the chain; nothing is chained after it and every credential of the agent is refused
(`401 agents/agent_inactive`, `error: agent_revoked`). An execution holds the agent's row for its
transaction, so the switch and an execution in flight serialise: an agent revoked or suspended
meanwhile runs nothing. `suspend` and `resume` pause an agent without sealing anything
(`agent_suspended`). A member who leaves an organization takes the agents and the hosts they registered
for it (the agents revoked and sealed, the hosts revoked); an erased user or organization leaves no
agent or host behind. The agent's OAuth client belongs to no organization: the plugin manages it (the
kill switch, its scopes, erasure), so the organization's self-service client routes
(`/orgs/{id}/oauth/clients`) never list, rewrite or delete it; operators see it under
`/admin/oauth/clients`.

## Capabilities with a location

A capability whose `location` is a host URL runs at the host, behind `AgentRequestMiddleware`, a PSR-15
middleware: the request must authenticate an agent (a JWT whose `aud` is the URL called, or an access
token) holding a live grant whose constraints the JSON body satisfies; the budget, the host's handler
and the receipt (outcome `success` for a 2xx, `failed` otherwise; the handler's exception rolls back and
is rethrown) run in one transaction. The handler reads the evaluated grant from the request attribute
`polaris.agents.grant` (and the agent from `polaris.agents.agent`, the whole context from
`polaris.agents.context`); the response carries `X-Polaris-Receipt`. `POST /agents/execute` refuses a
location capability: it cannot be reached without passing the middleware. Two ways to attach it:

- **Bound to the capability** (preferred): `AgentsPlugin::of($graph)->requestMiddleware($graph,
  'billing.refund')` on that capability's route. Every request through it is an execution of that
  capability, whatever URL the application sees; nothing passes through.
- **Unbound**: `requestMiddleware($graph)` in front of all routes. A request is matched against the
  locations by host, port and path, normalised (lower-case scheme and host, default port dropped, `//`
  collapsed, dot segments resolved, percent-encoded unreserved characters decoded, trailing slash
  dropped; the scheme is ignored), so no spelling of a location passes unguarded; any other URL passes
  through untouched.

In both forms the JWT's `aud` must be the URL called, compared normalised the same way (query and
fragment excluded). Behind a TLS-terminating proxy the application must see the external scheme, host
and port in PSR-7 (`X-Forwarded-*` handled before this middleware): a location requested as `http://`
is guarded but every agent JWT then fails with `aud_mismatch`, and in the unbound form a URL seen with
another host or port is not a location at all.

## MCP tools

With `polaris/mcp` registered, every capability with a handler the calling agent holds a live grant for
is a tool named `agents.<capability>` whose input schema is the capability's `input`; a call is an
execution with the same checks and receipt, answered as the HTTP route would (`{data, receipt}`, or the
problem document). The discovery document then advertises `endpoints.mcp`.

## Routes

| Route | Who | What |
| --- | --- | --- |
| `GET /.well-known/agent-configuration` | public | The discovery document (cached an hour). |
| `GET /agents/capabilities` | public, or an agent | The capabilities, `grant_status` for an agent. |
| `POST /agents/register` | the owner | An agent (`name`, `mode`, `auth`, `jwk`, `organization_id`, `capabilities`); the secret once. |
| `POST /agents/enroll` | a host (`Bearer peh_...`) | An agent under the host's owner with its default capabilities. |
| `GET /agents`, `GET /agents/{id}` | the owner | The agents, one with its grants. |
| `POST /agents/{id}/suspend`, `/resume`, `/revoke` | the owner | Pause, resume, the kill switch. |
| `GET /agents/{id}/receipts` | the owner | The chain (`after`, `limit`). |
| `GET /agents/receipts/{id}/verify` | the owner, or the agent | Hash, signature and chain checks. |
| `POST /agents/hosts`, `GET /agents/hosts`, `DELETE /agents/hosts/{id}` | the owner | Hosts; the enrolment token once. |
| `POST /agents/grants/request` | the agent | Grants, auto-approved or waiting in an approval. |
| `DELETE /agents/grants/{id}` | the owner | Revoke a grant. |
| `GET /agents/approvals`, `GET /agents/approvals/code?user_code=` | the owner | The pending approvals; the one behind a code. |
| `POST /agents/approvals/{id}/decide` | the owner | Approve or deny, once, with the strength required. |
| `POST /agents/execute` | the agent | Execute a capability with a handler. |
| `GET /agents/session` | the agent | The agent, owner, host, grants and budgets. |
| `GET /admin/agents`, `POST /admin/agents/{id}/revoke` | operators | Every agent; the kill switch. |

Rate groups: `register` for `/agents/register`; `token_refresh` for `/agents/enroll`, `/agents/execute`,
`/agents/grants/request` and `/agents/session`; `mfa_confirm` for `/agents/approvals/{id}/decide`.

## Configuration

| Option | Default | What |
| --- | --- | --- |
| `baseUrl` | required | Where Polaris is mounted, prefix included. |
| `capabilities` | `[]` | `Capability` objects or arrays (`name`, `description`, `input`, `permission`, `risk`, `handler` or `location`). |
| `autoApprove` | `['low' => ['count' => 100]]` | Risk tiers approved by policy when the owner holds the permission, with their budget (`true`: none). |
| `strengths` | `low`/`medium` `session`, `high` `step_up` | The approval strength per risk tier (`session`, `step_up`, `passkey`). |
| `approvalUrl` | null | The host's approval page (`verification_uri`); without it the default method is `in_app`. |
| `approvalTtl` | 600 | Seconds an approval stays pending. |
| `providerName`, `description` | `Polaris`, ... | The discovery document's provider. |
| `requestJwtMaxAge` | 300 | The most `exp - iat` a request JWT may span (at most 300). |
| `responses` | null | A PSR-17 response factory for the middleware's problem documents (discovered when absent). |

Problem types: `agents/unauthorized`, `agents/invalid_jwt`, `agents/aud_mismatch`,
`agents/agent_inactive` (`error` `agent_revoked` or `agent_suspended`), `agents/capability_not_found`,
`agents/capability_not_granted`, `agents/constraint_violated` (with `violations`),
`agents/budget_exhausted`, `agents/unknown_constraint_operator`, `agents/invalid_arguments`,
`agents/invalid_input`, `agents/not_found`, `agents/forbidden`, `agents/conflict`,
`agents/step_up_required`, `agents/permission_not_held`, `agents/sealed`. Where the protocol document
defines a code (the first eight), `error` carries it bare (`capability_not_granted`); the others carry the
plugin's prefix as every plugin's do (`agents_not_found`). A `401` answers `WWW-Authenticate: Bearer`
without a credential and `Bearer error="invalid_token"` with one that does not authenticate.

Events (PSR-14 `Polaris\Agents\Event\AgentEvent`, audited as `agent.*` with the agent as the actor where
it acts and the owner as the subject): `agent.registered`, `agent.enrolled`, `agent.suspended`,
`agent.resumed`, `agent.revoked`, `agent.grant.requested`, `agent.grant.approved`, `agent.grant.denied`,
`agent.grant.revoked`, `agent.grant.exhausted`, `agent.executed`, `agent.execution_denied`,
`agent.receipt.sealed`.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
