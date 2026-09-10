# Polaris for PHP on Symfony 7.4

The Symfony host: `polaris/symfony` as a bundle, SQLite through the bundle's DSN, emails written to
`var/mail.log`. The same walkthrough as the Slim and Laravel demos, from a clean clone in about a minute.

```sh
cd examples/symfony
composer install
bin/setup                       # .env, RS256 keys, polaris:schema:create, schema:diff, doctor
php -S 127.0.0.1:8080 -t public # in another terminal
bin/walkthrough.sh              # register → verify → login → TOTP → MFA login → organization → switch-org
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup && bin/walkthrough.sh` is enough.

## What the host provides

- [`config/packages/polaris.yaml`](config/packages/polaris.yaml): the secrets (from `.env`, PEM files by
  path), the issuer, the SQLite DSN and the mailer; everything else keeps core's default.
- [`config/routes.yaml`](config/routes.yaml): `type: polaris` mounts the 52 endpoints under
  `polaris.path_prefix` (`/`); `bin/console debug:router` lists them as `polaris.auth.login` and so on.
- [`config/packages/security.yaml`](config/packages/security.yaml): a stateless firewall on `/app` with
  `Polaris\Symfony\Security\PolarisAuthenticator`, so [`src/Controller/MeController.php`](src/Controller/MeController.php)
  gets a `PolarisUser` from a Polaris access token.
- [`config/services.yaml`](config/services.yaml): the demo's `FileMailer` (the JSON-lines mailbox).

`bin/console polaris:schema:create` creates the tables and seeds the permission catalog;
`polaris:schema:diff` and `polaris:doctor` check the deployment; `polaris:manifest --format=openapi`
renders the OpenAPI document; `polaris:schema:export` prints the DDL for another dialect.

Swap the DSN for PostgreSQL or MySQL (or `database: { service: doctrine.dbal.default_connection }` to reuse
Doctrine's connection), `mailer` for `mail` (Symfony Mailer) or your own `OtpMailerInterface` service, and
the same application runs in production.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
