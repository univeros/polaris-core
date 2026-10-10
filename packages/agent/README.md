# polaris/agent

The PHP agent SDK for [Polaris for PHP](https://github.com/univeros/polaris-core): discover a Polaris
server (`polaris/agents`), register or enrol an agent, request capability grants and wait for their
approval, sign request JWTs, execute capabilities, mint OAuth tokens (client credentials, token exchange)
and verify the signed receipt chain. For PHP agents, and for services calling each other as agents. Over
any PSR-18 client and PSR-17 factories; `firebase/php-jwt`, openssl and sodium do the signing. The
protocol is [`docs/better/agent-auth-compat.md`](../../docs/better/agent-auth-compat.md).

```sh
composer require polaris/agent
```

```php
use Polaris\Agent\AgentKey;
use Polaris\Agent\ApprovalException;
use Polaris\Agent\Http\StreamClient;
use Polaris\Agent\PolarisAgent;

$psr17 = new Nyholm\Psr7\Factory\Psr17Factory();                       // any PSR-17 factories
$http = new StreamClient($psr17, $psr17);                              // or Guzzle, Symfony's client, ... (any PSR-18 client)
$key = AgentKey::generate('ES256');                                    // or 'EdDSA'; keep $key->toArray() for the next run (AgentKey::fromArray)

$sdk = PolarisAgent::create('https://app.example.com/auth', $http, $psr17, $psr17, $key);   // reads <mount>/.well-known/agent-configuration
$enrolled = $sdk->enroll(getenv('POLARIS_ENROLLMENT_TOKEN'), ['name' => 'Worker', 'mode' => 'delegated']);
$agent = $sdk->bound($enrolled['id']);

$asked = $agent->requestGrants(['deploy.staging', ['name' => 'billing.refund', 'constraints' => ['amount' => ['max' => 50]]]]);
if (($asked['approval'] ?? null) !== null) {                           // what the policy did not approve waits for a person
    echo 'approve at ', $asked['approval']['verification_uri_complete'], PHP_EOL;
    $agent->waitForApproval($asked['approval']);                      // ApprovalException: denied, expired, cancelled
}
['data' => $data, 'receipt' => $receipt] = $agent->execute('deploy.staging', ['build' => '1.4.2']);
```

Every call of the agent is signed with its key: a request JWT (`typ: agent+jwt`) for the exact URL
called (`aud`, `htu`), the method (`htm`) and the exact body bytes (`body_hash`), 60 seconds long, with
a random `jti`; the server verifies it with the public JWK sent at registration. The private key stays in
the `AgentKey`; `toArray()` is for the agent's own storage.

## The API

| | |
| --- | --- |
| `PolarisAgent::discover($url, $client, $requests, $streams)` | The `Configuration` (the discovery document, its `mount`, `tokenEndpoint`, `mcpEndpoint()`). |
| `PolarisAgent::create($url, $client, $requests, $streams, $key?, $agentId?)` | `discover()` then `new PolarisAgent(...)`. |
| `AgentKey::generate($alg, $kid?)`, `fromPem()`, `fromSodiumSecretKey()`, `fromArray()`, `toArray()` | ES256 (P-256, openssl) or EdDSA (Ed25519, sodium); `kid` is the RFC 7638 thumbprint unless given. |
| `$agent->register($ownerToken, [...])` | By the owner (`name`, `mode`, `organization_id`, `capabilities`); `auth` is `private_key_jwt` with a key, else `client_secret` (the `pcs_` secret once). |
| `$agent->enroll($enrollmentToken, [...])` | Through a host (`peh_...`), under the host's owner with its default capabilities. |
| `$agent->bound($agentId)`, `$agent->withToken($accessToken)` | A new instance bound to the id; one sending that token instead of request JWTs. |
| `$agent->requestGrants($capabilities, [...])` | AAP's `{agent_id, agent_capability_grants, approval?}`; options `reason`, `preferred_method`, `binding_message`. |
| `$agent->waitForApproval($approval, $maxAttempts?, $cancelled?)` | Polls `GET /agents/session` every `interval` seconds (+5 s on a 429 or `slow_down`) until the grants are active. |
| `$agent->execute($capability, $arguments, $capabilities?)` | `['data' => ..., 'receipt' => ['id', 'seq', 'hash']]`; `$capabilities` restricts the grants the JWT may use. |
| `$agent->session()`, `$agent->capabilities()` | The agent, owner, host and grants with their budgets; the capabilities with `grant_status`. |
| `$agent->token([...])` | Client credentials (a `private_key_jwt` assertion, or the client secret as HTTP Basic); with `subject_token`, the RFC 8693 exchange of a user's token for a delegated one. `resource` names the MCP server. |
| `$agent->verifyReceipt($receipt, $previous?)` | Recomputes the hash as the server canonicalises it, verifies the `receipt+jwt` signature with `/auth/.well-known/jwks.json`, checks the link to `$previous`. |

The instance is immutable. A refusal is an `AgentException` with `status`, `error` (the problem's code:
`invalid_jwt`, `capability_not_granted`, `constraint_violated`, `budget_exhausted`, ...) and `problem`,
the RFC 9457 document (with `violations` when constraints failed). The clock and the pause of the poller
are injectable through the constructor (`now`, `sleep`) for tests.

`Polaris\Agent\Http\StreamClient` is a PSR-18 client over PHP's HTTP stream wrapper for an agent that
has none (a script, the Slim demo's `bin/agent-walkthrough.php`); a real HTTP client is the better choice
wherever one is installed.

## Generated from the manifest

`src/Routes.php` (the route table: method, path, path parameters, body fields) is generated by
`bin/generate-routes` from `packages/client-ts/openapi.json`, the client's rendering of the manifest,
filtered to the ten routes the SDK calls; it is checked in and drift-checked in CI. Hand-written are only
the cryptography (keys, request JWTs and assertions, receipt verification) and the loops (the approval
poller).

## Tests

```sh
vendor/bin/phpunit --testsuite agent      # the unit tests against a fake PSR-18 client, and the walkthrough through the PSR-15 pipeline
```

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
