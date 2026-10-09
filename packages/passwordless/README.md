# polaris/passwordless

Passwordless sign-in for [Polaris for PHP](https://github.com/univeros/polaris-core): magic links, email
one-time codes (to sign in, to verify the email, to reset the password), phone codes for a verified
second contact, and one-time tokens that hand a session to another device or domain. Every method ends in
core's login envelope, every secret works once, and an unknown address or number gets the same answer as
a known one.

```sh
composer require polaris/passwordless
```

```php
use Polaris\Audit\AuditPlugin;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Passwordless\PasswordlessPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new MessagingPlugin(channels: [$mail, $sms]),
    new PasswordlessPlugin(baseUrl: 'https://app.example.com/auth', redirectUris: ['https://app.example.com/signed-in']),
]));
```

`polaris/messaging` sends the links and codes (its `email.magic_link`, `email.otp` and `sms.otp`
templates, its channels and its per-recipient caps) and needs `polaris/audit`; register both first.
`baseUrl` is where Polaris is mounted, prefix included: the magic link points at `baseUrl/magic-link/verify`.
In Laravel, Symfony and Yii the instances go in the adapter's `plugins` configuration; the two tables
(`polaris_passwordless_secret`, `polaris_passwordless_phone`) join `polaris:install`, `schema:create` and
`schema:diff`, the routes join the route table.

## The methods

| Method | `amr` | Flow |
| --- | --- | --- |
| Magic link | `magic_link` | `POST /magic-link/send {email, redirect_uri?}` emails a link valid once for 15 minutes; the link (`GET /magic-link/verify?token=`) signs the user in and answers `302 <redirect_uri>?code=...`; `POST /magic-link/exchange {code}` answers the envelope, once, within a minute. Tokens never travel in the application's URL. |
| Email code | `email_otp` | `POST /email-otp/send {email}` emails a 6-digit code; `POST /email-otp/verify {email, code}` answers the envelope. |
| Phone code | `phone` | `POST /phone/send {phone}` texts a code to a user's verified phone; `POST /phone/verify {phone, code}` answers the envelope. A signed-in user adds the phone first: `POST /phone/add {phone}`, then `POST /phone/confirm {phone, code}`. |
| One-time token | the generating session's | `POST /one-time-token/generate` (bearer) answers a token valid once for 3 minutes; `POST /one-time-token/verify {token}`, on the other device or domain, answers a new session with the first one's `amr`, `mfa`, `auth_time` and organization. |

The email code also has two purposes beside signing in, as code alternatives to core's link flows (which
stay as they are): `POST /email-otp/send {email, purpose: "verify-email"}` then
`POST /email-otp/verify-email {email, code}`, and `purpose: "reset-password"` then
`POST /email-otp/reset-password {email, code, password}`, which checks core's password policy, lifts a
lockout and ends every session, as core's reset does. A code is bound to its purpose and to its address.

### The rules every method keeps

- **Same answer:** every send answers `202 {data: {status: "sent"}}` whether or not anything was sent;
  a wrong code and an unknown address or number answer the same `422 passwordless/code_invalid`.
- **Single use:** a secret is spent by a conditional update, so two concurrent verifies cannot both win;
  an expired or spent link, code or token is refused.
- **Attempts:** every guess reserves one of 5 attempts atomically, so parallel guesses cannot exceed
  them; a new code for the same address and purpose replaces the previous one and inherits its attempts
  while it lives, so sending again does not reset the count (after 5 wrong guesses, a code works again
  once the last one has expired).
- **Stored hashed:** links, codes, tokens and the addresses they were sent to are keyed hashes under
  core's pepper, never the values.
- **MFA:** a user with a confirmed MFA factor gets core's `mfa_required` ticket instead of a session and
  completes it at `/auth/mfa/verify` (`respectMfa: false` turns this off). A one-time token skips the gate:
  the session it transfers already passed it.
- **Sign-up:** an unknown email that proves its mailbox (magic link, email code) becomes a user, verified
  and without a password, unless `signUp: false`; then it gets nothing and the same answer. An unverified
  user who proves the mailbox by signing in becomes verified and loses the password set at registration
  (nobody had proved the mailbox for it; the owner sets one by reset). A phone never signs anybody up.
- **One-time tokens** die with the session that generated them.
- **Adding a phone** is a `step_up` route: a user with MFA and a stale `auth_time` steps up first.

## Routes

| Route | Who | Rate limit |
| --- | --- | --- |
| `POST /magic-link/send` `{email, redirect_uri?}` | public | `mfa_send` |
| `GET /magic-link/verify?token=` | public (the email's link) | `token_consume` |
| `POST /magic-link/exchange` `{code}` | public | `token_consume` |
| `POST /email-otp/send` `{email, purpose?}` | public | `mfa_send` |
| `POST /email-otp/verify` `{email, code}` | public | `token_consume` |
| `POST /email-otp/verify-email` `{email, code}` | public | `token_consume` |
| `POST /email-otp/reset-password` `{email, code, password}` | public | `token_consume` |
| `POST /phone/send` `{phone}` | public | `mfa_send` |
| `POST /phone/verify` `{phone, code}` | public | `token_consume` |
| `POST /phone/add` `{phone}` | bearer | `mfa_send` |
| `POST /phone/confirm` `{phone, code}` | bearer | `token_consume` |
| `POST /one-time-token/generate` | bearer (a live session) | |
| `POST /one-time-token/verify` `{token}` | public | `token_consume` |

The rate limits are core's groups, per IP. Errors are problem documents: `passwordless/invalid_input`
(with `errors`), `passwordless/redirect_not_allowed`, `passwordless/code_invalid`,
`passwordless/token_invalid`, `passwordless/password_invalid`, `passwordless/account_disabled`,
`passwordless/phone_taken`, `passwordless/session_required`. The TypeScript client has every route as
`client.passwordless.*`.

## Sentinel

With `polaris/sentinel`, add the plugin's routes to sentinel's guarded list so it judges the sends and
the code sign-ins as it judges core's:

```php
new SentinelPlugin(routes: SentinelMiddleware::ROUTES + PasswordlessPlugin::SENTINEL_ROUTES);
```

## Configuration

```php
new PasswordlessPlugin(
    baseUrl: 'https://app.example.com/auth',
    redirectUris: ['https://app.example.com/signed-in'],   // exact URLs a magic link may end on; the first is the default
    signUp: true,            // an unknown email that proves its mailbox becomes a user
    respectMfa: true,        // core's MFA gate applies to magic links, email and phone codes
    magicLinkTtl: 900,       // seconds
    otpTtl: 300,
    otpLength: 6,            // 6 to 10 digits
    maxAttempts: 5,
    oneTimeTokenTtl: 180,
);
```

The magic link's hand-off code lives a minute in the graph's cache: share it across web nodes as you
share core's rate store. Sends are as synchronous as messaging's outbox: with a slow channel, a queued
outbox keeps a known address from answering measurably later than an unknown one.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
