# polaris/mcp

[Polaris for PHP](https://github.com/univeros/polaris-core) and the Model Context Protocol, two halves in one
package: protect any PHP MCP server with Polaris-issued tokens (RFC 9728 metadata, local JWT verification,
DPoP binding, the `insufficient_scope` step-up), and serve Polaris itself as an MCP server, where every
endpoint (core and plugins) and every CLI command is a tool an agent calls under the caller's own
permissions.

```sh
composer require polaris/mcp
```

```php
use Polaris\Mcp\McpPlugin;
use Polaris\OAuth\OAuthPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new AdminPlugin(),
    new OAuthPlugin(
        baseUrl: 'https://app.example.com/auth',
        audiences: ['https://app.example.com/auth/mcp'],   // tokens minted for the MCP resource are accepted on every route
        ...
    ),
    new McpPlugin(
        baseUrl: 'https://app.example.com/auth',
        requests: $psr17, responses: $psr17, streams: $psr17,   // PSR-17 factories (Nyholm, Laminas, ...)
    ),
]));
```

`baseUrl` is where Polaris is mounted, prefix included: the MCP resource is `<baseUrl>/mcp`, its metadata
`<baseUrl>/.well-known/oauth-protected-resource/mcp`, and the tools dispatch their calls to the routes under
it. The plugin has no tables. `polaris/oauth-provider` is where the tokens come from: an MCP client reads the
metadata, finds core's issuer, obtains an access token for the resource (`resource=<baseUrl>/mcp` on the
token endpoint; client ID metadata documents are on by default, as the MCP profile expects) and presents
it. `audiences` on `OAuthPlugin` makes the oauth plugin's resolver accept those tokens as principals, which
is what lets a tool call run its route. In Laravel, Symfony and Yii the instance goes in the adapter's
`plugins` configuration; the two routes join the route table.

## Polaris as an MCP server

`POST /mcp` speaks the 2026-07-28 stateless profile (one JSON-RPC request per HTTP request, the
`MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers); `legacy: 'allow'` serves the 2025 session
handshake too, with sessions in the PSR-16 cache. Built on the official `mcp/sdk`, behind
`Polaris\Mcp\Transport\{Stdio,Http}`.

**Tools.** One per manifest route, named `polaris.` plus the spec file's path under `api/` with `/` and
`-` read as `.`: `polaris.auth.me`, `polaris.orgs.members.list`, `polaris.oauth.token`,
`polaris.admin.users.ban`. The input schema is the route's OpenAPI operation folded into one object (path
parameters, query parameters, body properties, with `required`); the output schema is `{status, body}` with
the body typed from the spec's example; `readOnlyHint` and `destructiveHint` follow the route's `effect`.
A call is dispatched in-process through the whole Polaris pipeline (rate limits, step-up, denylist,
authorization, every plugin's middleware) as a request to the route, so it answers exactly what the route
answers: `structuredContent: {status, body}`, the body as text content, `isError` for a 4xx or 5xx.

The list is the caller's: public routes (never an `mfa_token` one), bearer routes whose permissions the
caller's authority holds and core's delegation rule allows (a token with scopes may read and use its
permissions; it may not call a permissionless write nor a step-up route), routes tagged `admin` for an
operator the admin plugin recognises. Plugins add tools by implementing `Polaris\Mcp\ToolProvider`
(`polaris/agents`: every capability). The principal of a call travels as a request attribute the plugin's
bearer resolver returns, never as a header, so a DPoP-bound token proven once at `/mcp` serves every inner
call; the admin plugin's routes, which authenticate from the header alone, are the one exception (an
operator key or a session, never a bound token).

**Resources.** `polaris://manifest` (the OpenAPI document of every route), `polaris://schema` (the DDL
`bin/polaris schema:export` prints), and the template `polaris://problems/{plugin}/{name}` (a plugin's
problem type as the manifest declares it: its URL, statuses and routes).

**Over stdio**, for a local coding agent:

```sh
POLARIS_BOOTSTRAP=/path/to/polaris.php POLARIS_MCP_TOKEN=pk_... bin/polaris mcp
```

`POLARIS_BOOTSTRAP` names a file returning the application's `Polaris` instance or its `Config` (so the
plugins and their routes are known; the `mcp` command exists only then); `--token` or `POLARIS_MCP_TOKEN`
is the credential to act as: a session token, an API key (`pk_`, `polaris/api-keys`), an OAuth access
token, an operator key (`pak_`, `polaris/admin`); none for the public tools alone. Here the read-only CLI
commands are tools too (`polaris.schema.export`, `polaris.schema.diff`, `polaris.manifest`,
`polaris.doctor`), never over HTTP. A `.mcp.json` for Claude Code:

```json
{
  "mcpServers": {
    "polaris": {
      "command": "vendor/bin/polaris",
      "args": ["mcp"],
      "env": { "POLARIS_BOOTSTRAP": "config/polaris.php", "POLARIS_MCP_TOKEN": "pk_..." }
    }
  }
}
```

## Protecting an MCP server with Polaris

`McpProtectedResource` is PSR-15 middleware for any PHP MCP server, in the same process as
`polaris/oauth-provider` or against a remote issuer. It verifies the access token locally: the signature by
`kid` (local PEM keys, or the issuer's JWKS fetched once through a PSR-18 client and cached), `iss`, an `aud`
naming the resource, `exp` and `nbf` with a minute's leeway; a DPoP-bound token (`cnf.jkt`) must come with
the `DPoP` scheme and a proof for the request and the token (five minutes, used once), a bearer one with
`Bearer`. Then the required scopes. The verified claims reach the handler as the request attribute
`McpProtectedResource::CLAIMS`.

```php
use Polaris\Mcp\Protect\{Jwks, McpProtectedResource, TokenVerifier};

// A remote issuer:
$verifier = TokenVerifier::withJwks(
    issuer: 'https://auth.example.com',
    audiences: ['https://tools.example.com/mcp'],
    jwks: new Jwks('https://auth.example.com/auth/.well-known/jwks.json', $psr18, $psr17, $psr16),
    clock: $clock,
);
// Or local keys: TokenVerifier::withKeys($issuer, $audiences, ['<kid>' => $pem], $clock)
// Or Polaris's own: McpProtectedResource::fromGraph($graph, $resource, $psr17)

$middleware = new McpProtectedResource(
    resource: 'https://tools.example.com/mcp',
    verifier: $verifier,
    responses: $psr17, cache: $psr16, clock: $clock,
    scopes: ['deploy'],          // required of every request
    legacy: 'reject',            // or 'allow'
    resourceName: 'Deploy tools',
);
```

| Answer | When |
| --- | --- |
| `401`, `WWW-Authenticate: Bearer resource_metadata="<url>"`, problem `mcp/unauthorized` | No token. The client reads the metadata and finds the authorization server. |
| `401`, `... error="invalid_token", error_description="...", resource_metadata="..."` | A token that does not verify, is for another resource or issuer, expired, or presented against its binding. |
| `403`, `... error="insufficient_scope", scope="<missing>", resource_metadata="..."`, problem `mcp/insufficient_scope` with `missing_scopes` | A token short of a required scope; the client steps up for the named scopes. |
| `400`, problem `mcp/legacy_protocol` | With `legacy: reject`: an `Mcp-Session-Id` header, an `MCP-Protocol-Version` before 2026-07-28, or an `initialize` call. |

Standalone, it serves its own RFC 9728 document at `GET /.well-known/oauth-protected-resource<resource
path>` (`resource`, `authorization_servers`, `scopes_supported`, `bearer_methods_supported`,
`dpop_signing_alg_values_supported`, `resource_name`); `metadataUrl` moves it. Polaris's own `/mcp` serves
it as a route, under the mount.

## Configuration

| Option | Default | What |
| --- | --- | --- |
| `baseUrl` | required | Where Polaris is mounted, prefix included. |
| `requests`, `responses`, `streams` | required | PSR-17 factories; the SDK's transports and the in-process dispatch use them, so `php-http/discovery` is never needed. |
| `scopes` | `[]` | Scopes a token must hold to reach `/mcp` at all; each tool call is then checked by its own route. |
| `legacy` | `reject` | `reject` (the 2026-07-28 profile only) or `allow` (the 2025 handshake too, sessions in the cache). |
| `serverName` | `Polaris` | The server's name in MCP and the metadata's `resource_name`. |
| `logger` | null | PSR-3, for the SDK. |

Problem types: `mcp/unauthorized`, `mcp/insufficient_scope`, `mcp/legacy_protocol`.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
