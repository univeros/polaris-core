# polaris/passkey

Passkeys for [Polaris for PHP](https://github.com/univeros/polaris-core): WebAuthn registration from a
session, discoverable sign-in with conditional UI (the browser offers the user's passkeys, autofill
included) ending in core's login envelope, naming and removal; and, by default, every passkey is also a
core MFA factor, verified through core's own `/auth/mfa/verify` and `/auth/mfa/step-up`.

```sh
composer require polaris/passkey
```

```php
use Polaris\Passkey\PasskeyPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new PasskeyPlugin(origins: ['https://app.example.com'], rpName: 'App'),
]));
```

`origins` are the exact origins the browser pages live on; the relying party id (the domain the
passkeys are bound to) is the first origin's host unless `rpId` says otherwise; `http://localhost` is the
only plain-http origin accepted (development). In Laravel, Symfony and Yii the instance goes in the adapter's
`plugins` configuration; the table (`polaris_passkey`) joins `polaris:install`, `schema:create` and
`schema:diff`, the routes join the route table. Core's 52 routes are unchanged; the plugin registers its
factor type through core's `MfaFactorTypeProvider` seam.

## The ceremonies

The browser side is `navigator.credentials` with the options each route answers; the TypeScript
client's `registerPasskey()` and `signInWithPasskey()` wrap it.

1. **Register** (a session): `POST /passkey/register/options` answers
   `PublicKeyCredentialCreationOptionsJSON` (a discoverable credential is requested, the user's
   existing passkeys are excluded, the challenge lives five minutes). The browser's answer goes to
   `POST /passkey/register/verify {credential, name?}`; the attestation is verified against the
   challenge, the relying party and the origins (`none` attestation: which authenticator it is is not
   verified), and the passkey is stored. When passkeys are factors (the default) it is also a
   confirmed core factor of type `passkey`, and the first factor answers the recovery codes, as core's
   enrolments do.
2. **Sign in** (no session): `POST /passkey/authenticate/options` answers
   `PublicKeyCredentialRequestOptionsJSON` with no credential named, so the authenticator offers the
   user's passkeys and conditional UI can autofill them. `POST /passkey/authenticate/verify {credential}`
   verifies the assertion (the stored public key, the signature counter, the origin) and answers core's
   login envelope with `amr: ["passkey"]`.
3. **Second factor**: after a password login (or any sign-in) that answers `mfa_required`, the client
   fetches `POST /passkey/authenticate/options` and sends the assertion as the `code` of core's
   `POST /auth/mfa/verify {factor_id, code}`; `POST /auth/mfa/step-up` works the same. Core's
   `/auth/mfa/challenge` answers `unsupported_factor` for a passkey, as it does for TOTP: the options
   route is the challenge. The session core mints after the second step is its own (`amr: ["pwd","otp"]`).

### User verification and the MFA gate

An assertion whose authenticator verified the user (Face ID, a PIN, a fingerprint: the `UV` flag) is
two factors in one, so the session carries `mfa: true` and core's MFA gate is skipped. Without user
verification the passkey is one factor: a user with another confirmed factor gets core's `mfa_required`
ticket and completes the second step (the signing passkey is not offered as its own second factor), and
a user whose only factor is that passkey is refused with `passkey/user_verification_required`.
`userVerification: 'required'` asks the authenticator for it on every ceremony. A user core requires to
verify their email signs in with a passkey only once it is verified (`passkey/email_unverified`), as
with a password.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `POST /passkey/register/options` | bearer, `step_up` | the creation options |
| `POST /passkey/register/verify` `{credential, name?}` | bearer, `step_up` | stores the passkey (and its factor); `201` with `passkey` and `recovery_codes` |
| `POST /passkey/authenticate/options` | public | the request options, discoverable |
| `POST /passkey/authenticate/verify` `{credential}` | public, rate limit `login` | core's login envelope, or `mfa_required` |
| `GET /passkey/list` | bearer | the caller's passkeys: `id`, `name`, `aaguid`, `transports`, `backed_up`, `factor_id`, `last_used_at`, `created_at` |
| `PATCH /passkey/{id}` `{name}` | bearer | renames the passkey and the factor it backs |
| `DELETE /passkey/{id}` | bearer, `step_up` | removes the passkey and its factor; `passkey/last_factor` when core's enforcement protects it |

`credential` is the `PublicKeyCredential` JSON (`credential.toJSON()`), as an object or its string.
Errors are problem documents: `passkey/invalid_input`, `passkey/origin_mismatch` (the credential was
signed for another origin or relying party), `passkey/challenge_invalid` (unknown, used or expired),
`passkey/credential_invalid` (an unknown credential, a bad signature, a counter that did not move),
`passkey/account_disabled`, `passkey/email_unverified`, `passkey/user_verification_required`,
`passkey/not_found`, `passkey/last_factor`. The TypeScript client has every route as `client.passkey.*`.
Registration is step-up gated like core's factor removal: a passkey with user verification signs in past
the MFA gate, so a stolen access token alone must not register one.

Removing the factor through core's `DELETE /auth/mfa/factors/{id}` keeps the passkey as a sign-in
credential; removing the passkey removes its factor too.

## Configuration

```php
new PasskeyPlugin(
    origins: ['https://app.example.com', 'http://localhost:5173'],
    rpId: 'example.com',          // the first origin's host by default; a parent domain covers its subdomains
    rpName: 'App',                // what the authenticator shows
    mfaFactor: true,              // every passkey is also a core MFA factor
    userVerification: 'preferred', // or required, discouraged
    attachment: null,             // platform, cross-platform or no preference
    timeout: 60000,               // milliseconds, for the browser
    challengeTtl: 300,            // seconds a challenge waits in the cache
);
```

The challenges live in the graph's cache: share it across web nodes as you share core's rate store.

## Sentinel

With `polaris/sentinel`, add the sign-in route to sentinel's guarded list:

```php
new SentinelPlugin(routes: SentinelMiddleware::ROUTES + PasskeyPlugin::SENTINEL_ROUTES);
```

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
