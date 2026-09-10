# Polaris for PHP on Univeros 2

The Univeros host: the framework's own PSR-15 pipeline (Relay) with `polaris/psr15` serving the Polaris
routes ahead of the dispatcher, `polaris/pdo` on a SQLite file, emails written to `var/mail.log`. The
same walkthrough as the Slim, Laravel, Symfony and Yii demos, from a clean clone in about a minute.

```sh
cd examples/univeros
composer install
bin/setup                       # .env, RS256 keys, polaris schema:create, schema:diff, doctor
php -S 127.0.0.1:8080 -t public # in another terminal
bin/walkthrough.sh              # register → verify → login → TOTP → MFA login → organization → switch-org
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup && bin/walkthrough.sh` is enough.

## What the host provides

The application is the Univeros skeleton (`composer create-project univeros/univeros`): `config/container.php`
builds the container and applies the configurations and modules, `config/routes.php` holds the
application's own routes (`GET /ping`, the skeleton's health endpoint, still there), `public/index.php`
runs the Relay pipeline. Two files add Polaris:

- [`src/PolarisModule.php`](src/PolarisModule.php), registered in `config/modules.php`: builds Polaris from
  the environment (`Polaris::create()` with `EnvironmentConfig`, a `PdoAdapter`, the `FileMailer` mailbox
  and a PSR-14 dispatcher fed by `Polaris::listeners()`) and binds `Polaris`, `Graph`, the `Pipeline` and
  the middleware in the container.
- [`src/PolarisMiddleware.php`](src/PolarisMiddleware.php), placed before `DispatcherMiddleware` in
  `public/index.php`: a request whose path is in the manifest runs through the whole Polaris stack and
  handler (`Pipeline::handle()`); any other path continues to the framework's dispatcher.

`vendor/bin/polaris schema:create`, `schema:diff` and `doctor` run with `--dsn`; `vendor/bin/polaris manifest
--format=openapi` renders the OpenAPI document.

The 1.0 `univeros/polaris` module wired Polaris's tokens into the framework's own
`TokenAuthenticationMiddleware` for the application's routes; that bridge is not part of this demo
(a `polaris/univeros` package would carry it), so the application's routes here are public.

Swap the SQLite DSN for PostgreSQL or MySQL, the file mailer for your transport, and the dispatcher for
your own, and the same code runs in production.
