# polaris/anonymous

Guest sessions for [Polaris for PHP](https://github.com/univeros/polaris-core): a visitor gets a session
before they have an account, and once they sign up or in by any method the guest is converted into that
account through a hook where the application moves what it kept under the guest's id. The guests nobody
converted are pruned.

```sh
composer require polaris/anonymous
```

```php
use Polaris\Anonymous\AnonymousPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AnonymousPlugin(onConvert: function (string $guestId, string $userId): void {
        $carts->reassign($guestId, $userId);
    }),
]));
```

In Laravel, Symfony and Yii the instance goes in the adapter's `plugins` configuration; the table
(`polaris_anonymous`) joins `polaris:install`, `schema:create` and `schema:diff`, the routes join the route
table, the prune command joins the console.

## The guest

`POST /anonymous/sign-in` creates a core user with the placeholder email `<id>@anonymous.invalid`
(RFC 2606, it can receive nothing), no password and no organization, and answers core's login envelope
(`201`); the session's `amr` is `["anonymous"]`. The guest is an ordinary bearer for your own routes.

## The conversion

When the guest signs up or in (any method: core's `/auth/register` and `/auth/login`,
`polaris/passwordless`, `polaris/sso`, ...), the application calls `POST /anonymous/convert` with the
guest's access token as the bearer and the new account's access token in the body:

```http
POST /anonymous/convert
Authorization: Bearer <guest access token>

{"access_token": "<the account's access token>"}
```

The account's token must be a live session of another, real account. `onConvert(guestId, userId)` runs
first; if it throws, nothing is converted. Then the conversion is recorded, the guest's sessions end and
the guest is disabled. Its id stays, so whatever the application still keeps under it is reachable.
Answers `{data: {guest_id, user_id, status: "converted"}}`.

Errors are problem documents: `403 anonymous/not_a_guest` (the bearer is not a guest waiting, or was
converted already), `422 anonymous/token_invalid`, `422 anonymous/invalid_input`. The TypeScript client
has both routes as `client.anonymous.*`.

## Pruning

```sh
polaris anonymous:prune --bootstrap=bootstrap/polaris.php
```

deletes the unconverted guests older than `pruneAfterDays` (30 by default) with their core rows (user,
sessions, factors, challenges), and dispatches core's `UserDeleted` for each, so your listeners can drop
what you kept for them. Converted guests are kept. Run it from cron.

## Configuration

```php
new AnonymousPlugin(
    onConvert: fn(string $guestId, string $userId) => ...,   // optional
    pruneAfterDays: 30,
);
```

## Sentinel

With `polaris/sentinel`, add the sign-in route to sentinel's guarded list (a guest is judged as a
sign-up), and the route shares core's `register` rate limit:

```php
new SentinelPlugin(routes: SentinelMiddleware::ROUTES + AnonymousPlugin::SENTINEL_ROUTES);
```

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
