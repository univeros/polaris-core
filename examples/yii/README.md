# Polaris for PHP on Yii 3

The Yii host: `polaris/yii` as a `yiisoft/config` plugin, SQLite through the package's DSN, emails
written to `var/mail.log`. The same walkthrough as the Slim, Laravel and Symfony demos, from a clean
clone in about a minute.

```sh
cd examples/yii
composer install
bin/setup                       # .env, RS256 keys, polaris:schema:create, schema:diff, doctor
php -S 127.0.0.1:8080 -t public # in another terminal
bin/walkthrough.sh              # register → verify → login → TOTP → MFA login → organization → switch-org
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup && bin/walkthrough.sh` is enough.

## What the host provides

- [`config/params.php`](config/params.php): the `polaris` params that differ from the package defaults
  (the secrets from `.env`, PEM files by path, the issuer, the SQLite DSN, the mailer) and the middleware
  stack (`ErrorCatcher`, `RequestBodyParser`, `Router`).
- [`config/di.php`](config/di.php): what every Yii application has, PSR-17 factories, a logger, a file
  cache, and the demo's `FileMailer` (the JSON-lines mailbox).
- [`config/di-web.php`](config/di-web.php): the route collection from the `routes` group (the package's 52
  Polaris routes plus [`config/routes.php`](config/routes.php)) and the HTTP application.
- [`config/routes.php`](config/routes.php): `/app/me` behind the `polaris/authentication` middleware, so
  [`src/MeAction.php`](src/MeAction.php) gets a `PolarisIdentity` from a Polaris access token.

`./yii polaris:schema:create` creates the tables and seeds the permission catalog; `polaris:schema:diff` and
`polaris:doctor` check the deployment; `polaris:manifest --format=openapi` renders the OpenAPI document;
`polaris:schema:export` prints the DDL for another dialect.

Swap the DSN for PostgreSQL or MySQL (or leave it null and define `PDO` or a `Yiisoft\Db` connection in
the container), `mailer` for `mail` (the Yii mailer) or your own `OtpMailerInterface` id, and the same
application runs in production.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
