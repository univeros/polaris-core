# polaris/multi-session

Several signed-in accounts on one device for [Polaris for PHP](https://github.com/univeros/polaris-core):
the device lists its accounts, switches to one without signing in again, signs one out while the others
stay, and remembers how it last signed in so the client can pre-select that button.

```sh
composer require polaris/multi-session
```

```php
use Polaris\MultiSession\MultiSessionPlugin;

$polaris = Polaris::create(new Config(..., plugins: [new MultiSessionPlugin()]));
```

In Laravel, Symfony and Yii the instance goes in the adapter's `plugins` configuration; the table
(`polaris_multi_session_device`) joins `polaris:install`, `schema:create` and `schema:diff`, the routes join
the route table, the middleware joins the Polaris pipeline.

## The device

The plugin's middleware sees every Polaris response. One that carries a new token pair (any sign-in:
core's login and MFA verify, `polaris/passwordless`, `polaris/sso`, `polaris/username`, a refresh, a
switch) is recorded against the device, with the method the session signed in with (its first `amr`).
The device id is minted by the server: a request without one, or with one the server did not mint, gets a
new id, so nobody can attach a session to a device whose id they were not given. A sign-in that joins a
device that already has accounts gets the device a new id (the old one names nothing any more), so an id
planted in someone's browser does not give its owner the next account that signs in there; a refresh or
a switch keeps the id. It travels back as:

- the `X-Polaris-Device` response header, which a client that is not a browser sends back as the same
  request header (behind CORS, expose and allow that header);
- the HttpOnly cookie `polaris_ms_device` (`SameSite=Lax`, `Secure` over HTTPS), which a browser sends by
  itself. `new MultiSessionPlugin(cookie: false)` leaves only the header.

Only a hash of the id is stored.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `GET /multi-session/list` | bearer whose session is on the device | the device's live sessions, the most recent sign-in first: `session_id`, `user {id, email, display_name}`, `last_method`, `signed_in_at`, `last_seen`, `current` |
| `POST /multi-session/switch` `{session_id}` | bearer whose session is on the device | a new session for that account, without signing in again: it carries the old session's `amr`, `mfa`, `auth_time` and organization (core keeps them on the session row); the old session ends, the caller's stays. Core's login envelope. |
| `DELETE /multi-session/{sessionId}` | bearer whose session is on the device | ends that session (the caller's own included) and forgets it on the device; the others stay |
| `GET /multi-session/last-method` | public | `{data: {last_method}}`: `pwd`, `magic_link`, `email_otp`, `phone`, `sso`, `anonymous`, ...; null for an unknown device. No personal data. |

Errors are problem documents: `403 multi-session/device_unknown` (no device, or the bearer's session is
not on it), `404 multi-session/session_not_found` (not a live session of the device, or a disabled
account), `422 multi-session/invalid_input`. The TypeScript client has every route as
`client.multiSession.*`.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
