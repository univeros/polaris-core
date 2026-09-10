# Polaris for PHP on Laravel 13

The Laravel host: `polaris/laravel` discovered as a package, SQLite through Laravel's connection, emails
written to `storage/mail.log`. The same walkthrough as the Slim demo, from a clean clone in about a minute.

```sh
cd examples/laravel
composer install
bin/setup                       # .env, RS256 keys, polaris:install, migrate, schema:diff, doctor
php -S 127.0.0.1:8080 -t public # in another terminal
bin/walkthrough.sh              # register → verify → login → TOTP → MFA login → organization → switch-org
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup && bin/walkthrough.sh` is enough.

## What the host provides

- [`bootstrap/app.php`](bootstrap/app.php): a plain `Application::configure()`; the service provider is
  auto-discovered. The demo binds its `FileMailer` (the JSON-lines mailbox) as a singleton.
- [`config/polaris.php`](config/polaris.php): only what differs from the package defaults (the issuer and
  the mailer); secrets come from `.env` (`APP_KEY`, the `AUTH_JWT_*_FILE` PEM paths).
- [`config/auth.php`](config/auth.php): the `polaris` guard, so `Route::middleware('auth:polaris')` protects
  the application's own routes with Polaris access tokens (`$request->user()` is a `Polaris\Laravel\Auth\PolarisUser`).
- [`config/database.php`](config/database.php): SQLite at `database/polaris.sqlite`; Polaris uses that connection.

`php artisan polaris:install` publishes the config (already present here) and writes the migration that
creates the Polaris tables and seeds the permission catalog; `php artisan migrate` runs it;
`php artisan polaris:schema:diff` and `php artisan polaris:doctor` check the result; `php artisan route:list`
shows the 52 routes; `php artisan polaris:manifest --format=openapi` renders the OpenAPI document.

Swap the SQLite connection for PostgreSQL or MySQL, `mailer` for `mail` (Laravel's mailer with the
`polaris::mail.*` views) or your own `OtpMailerInterface`, and the same application runs in production.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
