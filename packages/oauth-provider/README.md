# polaris/oauth-provider

[Polaris for PHP](https://github.com/univeros/polaris-core) as an OAuth 2.1 and OpenID Connect provider:
authorization code with PKCE, refresh rotation, client credentials, the device flow, backchannel
authentication (CIBA), token exchange, DPoP-bound tokens, dynamic registration (off by default), client ID
metadata documents, discovery. Scopes are permissions: the access tokens it issues are accepted on every
Polaris route within their scopes, and by any resource server that verifies them against core's JWKS.

```sh
composer require polaris/oauth-provider
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\OAuth\OAuthPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new AdminPlugin(),
    new OAuthPlugin(
        baseUrl: 'https://app.example.com/auth',
        consentUrl: 'https://app.example.com/consent',
        deviceUrl: 'https://app.example.com/device',
        httpClient: $client, requestFactory: $requests,
    ),
]));
```

`polaris/audit` and `polaris/admin` are required and must be registered too: every token, consent and
client change is an `oauth.*` event in the audit store, and `/admin/oauth/clients` runs on the admin
plugin's principals. `baseUrl` is where Polaris is mounted, prefix included: the endpoints the
discovery documents advertise derive from it; the token issuer is core's `auth.issuer`. The PSR-18
client and PSR-17 request factory fetch client ID metadata documents and clients' `jwks_uri`. In
Laravel, Symfony and Yii the instance goes in the adapter's `plugins` configuration; the six tables
join `polaris:install`, `schema:create` and `schema:diff`, the routes join the route table.

## The flows

**Authorization code (PKCE S256, required).** The client sends the browser to `GET /oauth2/authorize`
with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` and
`code_challenge_method=S256` (and `nonce`, `resource`, `dpop_jkt`, `prompt` as it needs). The server
validates the request, parks it for ten minutes and sends the browser to the host's consent page with
`?request=<id>`; the page, with the user signed in, loads the request (`GET /oauth2/authorize?request=`:
the client, the scopes with their descriptions) and posts the decision (`POST /oauth2/authorize/decision`,
bearer, `{request, approve}`), which answers `redirect_to`: the redirect URI with `code`, `state` and
`iss` (RFC 9207). A trusted client, or scopes the user already granted, need no screen: the decision
endpoint answers the code without `approve`; a request that does need one answers `409
oauth/consent_required`. An XHR client gets the same data from the authorization endpoint with `Accept:
application/json`; a server without a `consentUrl` always answers JSON. `examples/slim/public/consent.html`
is a reference page.

**The token endpoint** (`POST /oauth2/token`, a form or JSON body) takes every grant with the client
authenticated the way it registered: `client_secret_basic`, `client_secret_post`, `private_key_jwt` (an
assertion signed with a key from the client's `jwks` or `jwks_uri`, `aud` the token endpoint, `jti` used
once) or `none` (a public client, PKCE). The response is RFC 6749's (`access_token`, `token_type`,
`expires_in`, `scope`, `refresh_token`, `id_token`), never cached; a refusal is an RFC 9457 problem
whose `error` is the RFC 6749 code (`invalid_grant`, `invalid_client` with `WWW-Authenticate`, ...),
with `error_description`.

| Grant | What |
| --- | --- |
| `authorization_code` | `code`, `code_verifier`, `redirect_uri`; a code is spent once. |
| `refresh_token` | Rotated at every use; `scope` may narrow, never widen; a spent token presented again revokes its whole family (RFC 9700 §4.14). |
| `client_credentials` | A confidential client's own token, no user, no refresh. |
| `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628: `POST /oauth2/device/code` answers the device and user codes, the user types the code on the host's device page (`GET /oauth2/device/verify?user_code=` shows the client, `POST /oauth2/device/approve` decides), the device polls with `device_code` (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`). |
| `urn:openid:params:grant-type:ciba` | OpenID CIBA, poll mode: `POST /oauth2/ciba` with `login_hint` (the user's email) and a `binding_message`; the user sees it in `GET /oauth2/ciba/pending` and decides with `POST /oauth2/ciba/{id}/decide`; the client polls with `auth_req_id`. The host notifies the user from the `oauth.ciba_requested` event. Because it reaches people by their email, only an operator grants it to a client. |
| `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693: `subject_token` (a Polaris session's access token, or one of this provider's), optional `actor_token`, `resource` or `audience`, `scope` within the subject's; the token carries `act` naming the client (and the actor), chained through further exchanges. |

**Access tokens** are JWTs (`typ: at+jwt`, RFC 9068) signed with core's key and `kid`, so
`/auth/.well-known/jwks.json` verifies them: `iss`, `sub` (the user, or the client for its own token),
`aud` (the `resource` asked for, or the issuer), `client_id`, `scope`, `org`, `jti`, `exp`, `cnf.jkt`
when DPoP-bound, `act` after an exchange. An ID token (`openid`) carries `sub`, `aud` (the client),
`nonce`, `auth_time`, and `email`, `email_verified` (`email` scope), `name`, `updated_at` (`profile`).
`GET|POST /oauth2/userinfo` answers the same claims for a token with `openid`. `POST /oauth2/introspect`
(RFC 7662) and `POST /oauth2/revoke` (RFC 7009) take the client's authentication; a revoked refresh
token takes its family with it.

## Scopes are permissions

A scope is a permission name from the catalog (`org.read`, `members.invite`, a plugin's), one of the
OpenID ones (`openid`, `profile`, `email`, `offline_access`), or an extra the host configures
(`scopes: ['deploy' => 'Deploy the application']`, for its own resource servers and the MCP tools of
`polaris/mcp`). A client may be limited to a list of scopes (`scopes` on the client; empty means any).

On a Polaris route, one of these access tokens authenticates as its user, in the token's organization,
with the permission scopes as the *delegated* authority (core's bearer-resolver seam): the authorization
middleware resolves the user's permissions from the database as always and intersects them with the
scopes, so a token never does more than its user may, and loses what the user loses. A delegate reads
and uses its permissions; it may not call a write route that needs no permission (the person's own
self-service: enrolling a factor, creating an organization, deciding a consent, minting a key) nor a
step-up route, and a superadmin's token carries no override. A token for another resource (`aud`
elsewhere) or for the client itself clears no permission check here. The user's own session is
untouched by any of it, and core's session parser never takes one of these tokens, nor an ID token, for
a session.

## Consent

A user's consent is one row per client with the scopes granted so far; a later request within them
needs no screen, a wider one asks for the whole set, `prompt=consent` always asks. `GET /oauth2/consents`
lists them; `DELETE /oauth2/consents/{clientId}` takes one back and revokes every token the client holds
for the user. An operator may mark a client *trusted* (`POST /admin/oauth/clients` with `trusted: true`,
or the plugin's `trustedClients`): its users are never asked, nothing is recorded.

## DPoP

A client may bind its tokens to a key (RFC 9449): a `DPoP` header on the token request (a JWT signed
with the key in its own `jwk` header, `htm`, `htu`, `iat`, `jti`) makes the tokens `token_type: DPoP`
with `cnf.jkt`; the refresh token is bound to the same key; a code may be bound ahead with `dpop_jkt`.
A bound token is presented as `Authorization: DPoP <token>` with a proof for the request and the
token (`ath`); a proof is good for five minutes and used once; the `Bearer` scheme, another key or a
replayed proof are refused. `dpop: 'required'` demands it of every client, `'off'` turns it off, and a
client registered with `dpop_bound_access_tokens` must prove a key.

## Clients

| Route | What |
| --- | --- |
| `GET|POST /orgs/{id}/oauth/clients`, `GET|PATCH|DELETE /orgs/{id}/oauth/clients/{clientId}` | An organization's clients, by a member with `org.update` in it. Confidential (a secret shown once, or a key) or public (`none`, PKCE); `redirect_uris` (https, http on loopback, or a reverse-domain custom scheme such as `com.example.app`), `grant_types` (CIBA excepted), `scopes`, `jwks` or `jwks_uri`, `dpop_bound_access_tokens`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`; `disabled` stops it. Never trusted. |
| `GET|POST /admin/oauth/clients`, `DELETE /admin/oauth/clients/{id}` | The operators' view (the admin plugin's roles): instance-wide or organization clients, `trusted` allowed. |
| `POST /oauth2/register` | RFC 7591 dynamic registration, off by default (`403 oauth/registration_disabled`); on, anyone registers a client, never trusted. |

**Client ID metadata documents** (`clientIdMetadata`, on by default, the MCP 2026 profile): a
`client_id` that is an `https` URL is fetched (over the PSR-18 client, at most 64 KiB), must carry
itself as `client_id`, is validated like a registration (`none` or `private_key_jwt` only) and cached
for an hour; a URL on a special-use address or name (loopback, private ranges, link-local, numeric
hosts, `localhost`, `.local`, `.internal`, `.onion`, `.test`, `.example`, `.invalid`, ...), on another
port than 443, or with credentials is refused; the same rule applies to a client's `jwks_uri`. The host
name is not resolved: a public name pointing at a private address is the host network's concern. A
metadata client acts for a user only (no `client_credentials`, no token exchange).

## Discovery

`GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server` (RFC 8414),
under the mount (`<baseUrl>/.well-known/...`, which is OpenID-conformant for an issuer with a path; a
host may alias the root form RFC 8414 derives), advertise exactly what is enabled: the endpoints, the
scopes, the grants (the device grant when `deviceUrl` is set, registration when it is on), the client
authentication methods, `S256`, the DPoP algorithms, `jwks_uri` = core's.

## Configuration

| Option | Default | What |
| --- | --- | --- |
| `baseUrl` | required | Where Polaris is mounted, prefix included. |
| `consentUrl`, `deviceUrl` | null | The host's consent page (null: JSON only) and device page (null: no device flow). |
| `httpClient`, `requestFactory` | null | PSR-18 and PSR-17, for metadata documents and `jwks_uri`. |
| `accessTokenTtl`, `refreshTokenTtl` | 3600, 2592000 | Seconds. |
| `codeTtl`, `deviceCodeTtl`, `cibaTtl`, `pollInterval` | 600, 1800, 600, 5 | Seconds; a zero interval turns the poll throttle off. |
| `dynamicRegistration` | false | RFC 7591. |
| `clientIdMetadata` | true | `https` client ids. |
| `dpop` | `optional` | `off`, `optional`, `required`. |
| `scopes` | `[]` | Extra scopes (name => description). |
| `trustedClients` | `[]` | Client ids whose users are not asked for consent. |

Problem types: `oauth/<RFC error>` (`invalid_request`, `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `invalid_target`, `invalid_dpop_proof`,
`invalid_token`, `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `unknown_user_id`,
`invalid_client_metadata`, `registration_disabled`, `consent_required`), `oauth/not_found`, `oauth/forbidden`.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
