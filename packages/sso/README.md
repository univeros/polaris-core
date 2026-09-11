# polaris/sso

SSO for [Polaris for PHP](https://github.com/univeros/polaris-core): per-organization SAML 2.0 and OpenID
Connect providers, verified domains that route an email to its organization's provider, just-in-time
users and memberships, single logout in both directions, the organization's own self-service routes
and the operators' view. No operator is needed to onboard an organization's identity provider.

```sh
composer require polaris/sso
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Sso\SsoPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new AdminPlugin(),
    new SsoPlugin(baseUrl: 'https://app.example.com/auth', httpClient: $client, requestFactory: $requests, streamFactory: $streams),
]));
```

`polaris/audit` and `polaris/admin` are required and must be registered too: every action is an `sso.*`
event in the audit store, and the operator routes use the admin plugin's principals. `baseUrl` is where
Polaris is mounted, prefix included: the SP entity id, the assertion consumer and single-logout URLs and
the OIDC redirect URI derive from it. OIDC needs the PSR-18 client and PSR-17 factories (discovery, the
token endpoint, the JWKS); SAML needs nothing more. In Laravel, Symfony and Yii the three instances go in
the adapter's `plugins` configuration; the two tables (`polaris_sso_provider`, `polaris_sso_domain`) join
`polaris:install`, `schema:create` and `schema:diff`, the routes join the route table.

## The sign-in

1. The application calls `POST /sso/sign-in` with the user's `email` (a verified domain routes it to its
   provider) or a `provider_id`, and optionally the `redirect_uri` the sign-in should end on (one of the
   provider's; the first by default). It answers `{data: {url, provider_id, type}}`; the application
   sends the browser to `url`.
2. The provider authenticates the user and sends the browser back to the callback
   (`GET /sso/callback/{providerId}` for OIDC, `POST` for SAML). Polaris validates what came back, finds
   the user by email or creates them (when the provider provisions), makes sure they are a member of the
   organization, opens a session scoped to that organization (`amr: ["sso"]`) and answers
   `302 <redirect_uri>?sso_code=...`. Tokens never travel in a URL.
3. The application calls `POST /sso/exchange` with the code, once, within a minute, and receives the login
   envelope (`access_token`, `refresh_token`, `user`), as `/auth/login` answers it.

A rejected assertion or token answers `403 sso/assertion_invalid` with a generic detail; the reason is in
the audit trail (`sso.assertion_rejected`). Every rejection and sign-in is audited; a sign-in is also
core's `UserLoggedIn`, a provisioned membership core's `MemberJoined`.

### What is checked

- **OIDC**: discovery from the issuer (cached an hour), the authorization code flow with PKCE (S256) and a
  nonce, the token endpoint with `client_secret_post`, the id_token verified against the provider's JWKS
  (a minute of leeway), its issuer, audience and nonce.
- **SAML 2.0** (onelogin/php-saml, strict): a signature on the response or the assertion with the
  provider's certificate, exactly one assertion (a smuggled second one is refused), the audience (the SP
  entity id), the destination and recipient (the assertion consumer URL), the conditions with three
  minutes of drift, `InResponseTo` matching the request the SP sent (an unsolicited, IdP-initiated
  response is accepted only when the provider sets `idp_initiated`), and the assertion id kept until it
  expires so a replay is refused. Logout requests must be signed (the redirect binding's query signature
  or an enveloped signature).

### Provisioning

A user is found by the asserted email. When none exists and the provider's `jit.enabled` is set, the user
is created with the email verified (the provider vouched for the mailbox), no password, the display name
from the mapped attribute; otherwise `403 sso/user_unknown`. A missing membership is created with the
roles of `jit.roles` (slugs of the organization's roles, `member` by default); a suspended membership
refuses the sign-in; a disabled account too.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /sso/sign-in` `{email \| provider_id, redirect_uri?}` | public | where to send the browser |
| `GET /sso/callback/{providerId}?code&state` | public | the OIDC callback; `302 redirect_uri?sso_code=` |
| `POST /sso/callback/{providerId}` `SAMLResponse, RelayState` | public | the SAML assertion consumer; `302 redirect_uri?sso_code=` |
| `POST /sso/exchange` `{code}` | public | the login envelope, once |
| `GET /sso/metadata/{providerId}` | public | the SP metadata XML (`application/samlmetadata+xml`) |
| `GET\|POST /sso/slo/{providerId}` | public | an IdP's signed LogoutRequest ends the user's sessions and is answered with the LogoutResponse redirect; an IdP's LogoutResponse ends an application-initiated logout |
| `POST /sso/logout` `{provider_id?, organization_id?, post_logout_uri?}` | bearer | the caller's sessions end; `url` is the IdP's single-logout (SAML LogoutRequest or OIDC end-session), null when the provider offers none |
| `GET\|POST /orgs/{id}/sso/providers`, `GET\|PATCH\|DELETE /orgs/{id}/sso/providers/{providerId}`, `POST .../test` | `org.update` in the active organization | the organization's providers (below) |
| `GET\|POST /orgs/{id}/sso/domains`, `POST /orgs/{id}/sso/domains/{domainId}/verify`, `DELETE /orgs/{id}/sso/domains/{domainId}` | `org.update` | the organization's domains |
| `GET /admin/sso/providers?organization_id=&cursor=&limit=`, `DELETE /admin/sso/providers/{id}` | admin read / own | every organization's providers, for the operators |

The organization routes are core's: `auth: bearer` with `org.update`, and the path's organization must be
the token's active one (a superadmin excepted). Their errors are problem documents (`sso/forbidden`,
`sso/not_found`, `sso/invalid_input` with `errors`, `sso/conflict`, `sso/domain_unverified`); the public
flow's are `sso/provider_not_found`, `sso/provider_disabled`, `sso/invalid_input`, `sso/assertion_invalid`,
`sso/user_unknown`, `sso/account_disabled`, `sso/membership_suspended`, `sso/code_invalid`. The TypeScript
client has every route as `client.sso.*`.

### A provider

```json
{
  "type": "oidc",
  "name": "Okta",
  "issuer": "https://acme.okta.com",
  "config": { "client_id": "0oa...", "client_secret": "...", "scopes": "openid email profile" },
  "attributes": { "email": "email", "name": "name" },
  "jit": { "enabled": true, "roles": ["member"] },
  "redirect_uris": ["https://app.example.com/sso/done"],
  "enabled": true
}
```

- `type` is `oidc` (config: `client_id`, optional `client_secret`, `scopes`, `issuer` when the discovery
  issuer differs) or `saml` (config: `sso_url`, the IdP's signing `certificate` as PEM or base64, optional
  `slo_url`, `slo_response_url`, `idp_initiated`). `issuer` is the OIDC issuer URL or the SAML IdP entity
  id.
- The client secret is encrypted at rest with core's encrypter and never returned; the API answers
  `client_secret_set`. A `PATCH` whose config omits it keeps it.
- `attributes` maps `email` and `name` onto the provider's claim or attribute names; for SAML the
  `NameID` is the email when no attribute carries one.
- `redirect_uris` lists the application URLs a sign-in may end on; the first is the default.
- `GET .../providers/{providerId}` also answers the `sp` side (`entity_id`, `acs_url`, `slo_url`,
  `metadata_url`) the IdP is configured with; `POST .../test` says whether the configuration is complete
  and, for OIDC, whether discovery and the JWKS are reachable.

### A domain

`POST /orgs/{id}/sso/domains {domain, provider_id}` claims a domain for a provider (one organization per
domain across the instance) and answers a token with two ways to prove it: a DNS TXT record
`_polaris.<domain>` or the file `https://<domain>/.well-known/polaris-sso.txt`, either carrying the token.
`POST .../verify` checks DNS then HTTPS (`DomainVerifier`, the system resolver and the plugin's PSR-18
client; your own implementation goes in `domains:`). Once verified, `POST /sso/sign-in {email}` routes the
domain's emails to the provider.

## Configuration

```php
new SsoPlugin(
    baseUrl: 'https://app.example.com/auth',
    httpClient: $client, requestFactory: $requests, streamFactory: $streams,   // PSR-18 and PSR-17, for OIDC and the HTTPS domain check
    spCertificate: $pem, spPrivateKey: $key,   // optional: signed AuthnRequests and logout messages, encrypted assertions, the certificate in the metadata
    oidc: new MyOidc(), saml: new MySaml(),    // optional: your own protocol implementations (the tests use fakes)
    domains: new MyDomainVerifier(),
);
```

Short-lived state (the OIDC state, nonce and PKCE verifier, the SAML request ids, the assertion ids
seen, the hand-off codes) lives in the graph's cache: share it across web nodes as you share core's
rate store.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
