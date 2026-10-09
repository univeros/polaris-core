# polaris/social

Social sign-in for [Polaris for PHP](https://github.com/univeros/polaris-core): OAuth 2.0 and OpenID
Connect through Google, Apple, Microsoft, GitHub and fifteen more providers, or any other OAuth 2 server;
sign-up and sign-in ending in core's login envelope, account linking under a policy, Google One Tap,
provider tokens on the user's behalf, and an OAuth proxy so preview and local origins sign in through
the stable one registered at the providers.

```sh
composer require polaris/social
```

```php
use Polaris\Audit\AuditPlugin;
use Polaris\Social\SocialPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new SocialPlugin(
        baseUrl: 'https://app.example.com/auth',
        providers: [
            'google' => ['client_id' => '...', 'client_secret' => '...'],
            'github' => ['client_id' => '...', 'client_secret' => '...'],
            'apple' => ['client_id' => 'com.example.app', 'team_id' => '...', 'key_id' => '...', 'private_key' => $pem],
            'microsoft' => ['client_id' => '...', 'client_secret' => '...', 'tenant' => 'common'],
        ],
        httpClient: $client, requestFactory: $requests, streamFactory: $streams,
        redirectUris: ['https://app.example.com/signed-in'],
    ),
]));
```

`polaris/audit` is required and must be registered too: every sign-in, link and refusal is a `social.*`
event in the audit store. `baseUrl` is where Polaris is mounted, prefix included: the callback each
provider is configured with is `baseUrl/social/<provider>/callback`. The PSR-18 client and PSR-17
factories talk to the providers. In Laravel, Symfony and Yii the instance goes in the adapter's
`plugins` configuration; the table (`polaris_social_account`) joins `polaris:install`, `schema:create`
and `schema:diff`, the routes join the route table.

## The sign-in

1. The application calls `POST /social/{provider}/start` with, optionally, the `redirect_uri` the sign-in
   should end on (one of the plugin's; the first by default) and `scopes`. It answers
   `{data: {url, state}}`; the application sends the browser to `url`.
2. The provider authenticates the user and sends the browser back to `GET /social/{provider}/callback`
   (`POST` for Apple's `form_post`). Polaris exchanges the code (PKCE where the provider takes it),
   reads the profile (the id_token verified against the provider's keys for an OpenID Connect
   provider), applies the linking policy and answers `302 <redirect_uri>?code=...&state=...`. Tokens
   never travel in a URL; the application compares `state` with the one `start` answered before it
   exchanges the code, so a flow it did not start (someone else's) is dropped.
3. The application calls `POST /social/exchange` with the code, once, within a minute, and receives
   the login envelope (`amr: ["social:<provider>"]`), or core's `mfa_required` ticket when the user has
   a confirmed MFA factor, to complete at `/auth/mfa/verify`.

### The linking policy

- A provider account seen before signs its user in.
- A provider in `trustedProviders` (`google` and `apple` by default) whose profile carries a verified
  email links to the existing user with that email and signs them in. When nobody had verified that
  user's email (it was registered with a password and never verified, or through a provider that did not
  vouch for it), the provider just proved the mailbox: the account becomes theirs, and the unproven
  password, the sessions and the other linked accounts go.
- Any other provider, or an unverified email, is refused with `409 social/account_exists` when the
  email belongs to an existing user: the user signs in and links the provider from their session.
- An unknown email signs up: a user without a password, verified when the provider vouched for the
  address (`signUp: false` refuses instead). A provider that shares no email is `social/email_required`;
  one that did not vouch for it makes an unverified account, which core's `require_verified_email` keeps
  out of a session (`social/email_unverified`) until the address is verified, as with a password.
- From a session, `POST /social/{provider}/link` (step-up gated) starts the same flow for the caller's
  account and `POST /social/exchange` answers `{status: "linked", account}`. A provider account linked
  to another user is `social/account_linked`; a provider email that is not the account's is
  `social/email_mismatch` unless the provider is in `allowDifferentEmails`.
- `DELETE /social/{provider}` unlinks, unless it is the only way into the account (no password, no other
  provider): `social/last_credential`.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /social/{provider}/start` `{redirect_uri?, scopes?}` | public | where to send the browser |
| `GET\|POST /social/{provider}/callback` | public | the provider's answer; `302 redirect_uri?code=` |
| `POST /social/exchange` `{code}` | public | the login envelope or the linked account, once |
| `POST /social/google/one-tap` `{credential}` | public | the One Tap id_token, verified offline, for the envelope |
| `GET /social/accounts` | bearer | the caller's linked accounts (never their tokens) |
| `POST /social/{provider}/link` `{redirect_uri?, scopes?}` | bearer, `step_up` | where to send the browser to link |
| `DELETE /social/{provider}` | bearer, `step_up` | unlinks |
| `POST /social/{provider}/token` | bearer, `step_up` | `{access_token, expires_at, scopes}` for the provider's API, refreshed when expiring |

Errors are problem documents: `social/provider_not_found`, `social/redirect_not_allowed`,
`social/state_invalid`, `social/provider_error` (what the provider refused is in the audit trail),
`social/token_invalid`, `social/email_required`, `social/email_mismatch`, `social/account_exists`,
`social/account_linked`, `social/account_disabled`, `social/email_unverified`, `social/not_linked`, `social/last_credential`,
`social/code_invalid`, `social/no_refresh`, `social/invalid_input`. The TypeScript client has every route
as `client.social.*`.

## Providers

The catalog: `google`, `apple`, `microsoft`, `github`, `gitlab`, `discord`, `facebook`, `x`, `linkedin`,
`slack`, `twitch`, `spotify`, `zoom`, `notion`, `dropbox`, `reddit`, `kick`, `tiktok`, `huggingface`. Each
is a `Definition` (endpoints, scopes, PKCE, OpenID Connect issuer, how its profile maps) behind one
`OAuth2Provider`; Apple (the client secret is a JWT the plugin signs with the team key; the name
arrives in the first callback only) and GitHub (the verified primary email from `/user/emails`) have
their own classes. Microsoft takes `tenant` (`common`, `organizations`, `consumers` or a tenant id).
A provider that shares no verified email (X without the approved field, Reddit, TikTok) cannot sign up
by itself; it links from a session.

Any other OAuth 2 server, Better Auth's `GenericOAuth`:

```php
'acme' => ['client_id' => '...', 'client_secret' => '...', 'definition' => new Definition(
    'acme', 'Acme', 'https://acme.example/oauth/authorize', 'https://acme.example/oauth/token', 'https://acme.example/oauth/me',
    ['profile'], fn(array $me): Profile => new Profile((string) $me['id'], $me['email'], (bool) $me['verified'], $me['name']),
)],
'okta' => ['client_id' => '...', 'client_secret' => '...', 'issuer' => 'https://acme.okta.com'],   // OpenID Connect discovery
```

## The OAuth proxy

Providers want one registered callback. With `proxy: 'https://auth.example.com'`, a deployment mounted
elsewhere (a preview, `http://localhost`) sends the provider to the stable origin's callback and puts
its own callback in the state, signed under core's pepper (which the deployments share through
`APP_KEY`). The stable origin's callback forwards a validly signed state to the preview's callback
with the code, and refuses a tampered or unsigned one (`social/state_invalid`); the preview completes
the exchange itself.

## Configuration

```php
new SocialPlugin(
    baseUrl: 'https://app.example.com/auth',
    providers: [...],
    httpClient: $client, requestFactory: $requests, streamFactory: $streams,
    redirectUris: ['https://app.example.com/signed-in'],   // exact; the first is the default
    trustedProviders: ['google', 'apple'],                 // auto-link by verified email
    allowDifferentEmails: ['github'],                      // may link from a session with another email
    signUp: true,
    respectMfa: true,                                      // core's MFA gate applies to social sign-ins
    proxy: null,
);
```

The state (ten minutes), the hand-off codes (a minute) and the providers' key sets (an hour) live in
the graph's cache: share it across web nodes as you share core's rate store.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
