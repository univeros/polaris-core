# polaris/username

Usernames for [Polaris for PHP](https://github.com/univeros/polaris-core): a user picks a username,
unique without regard to case, and signs in with it or with the email through core's own password path,
so lockout, the email-verification rule, the MFA gate and the envelope are core's.

```sh
composer require polaris/username
```

```php
use Polaris\Username\UsernamePlugin;

$polaris = Polaris::create(new Config(..., plugins: [new UsernamePlugin()]));
```

In Laravel, Symfony and Yii the instance goes in the adapter's `plugins` configuration; the table
(`polaris_username`) joins `polaris:install`, `schema:create` and `schema:diff`, the routes join the route
table. Core's `/auth/login` is untouched.

## Routes

| Route | Who | Does |
| --- | --- | --- |
| `PATCH /username` `{username, display_username?}` | bearer | sets or changes the caller's username |
| `POST /username/sign-in` `{username, password}` | public, rate limit `login` | `username` is a username (any case) or an email; answers core's login envelope, or its `mfa_required` ticket to complete at `/auth/mfa/verify` |

A username is stored lowercased (the unique column) beside the form the user typed
(`display_username`, the same letters in another case), so `Ada.Lovelace` and `ada.lovelace` are one
name on PostgreSQL, MySQL and SQLite alike, without collations; the unique index settles two users taking
the same name at once.

An unknown username, a wrong password and a live lockout answer the same
`401 username/invalid_credentials`, and an unknown username costs the same password check as an unknown
email. Other errors: `403 username/email_unverified`, `403 username/account_disabled`,
`422 username/invalid_input`, `422 username/invalid` (with `errors`), `409 username/taken`. The TypeScript
client has both routes as `client.username.*`.

## Rules

```php
use Polaris\Username\Rules;

new UsernamePlugin(new Rules(
    minLength: 3,
    maxLength: 30,
    pattern: '/^[A-Za-z0-9_.]+$/',
    reserved: [...Rules::RESERVED, 'billing'],   // compared without regard to case
));
```

## Sentinel

With `polaris/sentinel`, add the sign-in route to sentinel's guarded list:

```php
new SentinelPlugin(routes: SentinelMiddleware::ROUTES + UsernamePlugin::SENTINEL_ROUTES);
```

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
