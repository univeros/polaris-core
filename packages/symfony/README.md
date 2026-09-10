# polaris/symfony

[Polaris for PHP](https://github.com/univeros/polaris-core) in a Symfony 7.4 or 8 application: a
bundle that builds Polaris from the `polaris:` configuration on the application's connection, cache,
logger, event dispatcher and mailer; the 52 endpoints as routes through the `polaris` route loader; an
authenticator for your own firewalls; the `polaris:*` console commands. Every response is the one the
framework-free core sends: the whole functional suite and the 184 contract fixtures replay through
Symfony's HTTP kernel in CI.

## Install

```sh
composer require polaris/symfony
```

```php
// config/bundles.php
Polaris\Symfony\PolarisBundle::class => ['all' => true],
```

```yaml
# config/packages/polaris.yaml
polaris:
    secrets:
        app_key: '%env(POLARIS_APP_KEY)%'            # at least 32 bytes
        jwt_private_key_file: '%env(AUTH_JWT_PRIVATE_KEY_FILE)%'
        jwt_public_key_file: '%env(AUTH_JWT_PUBLIC_KEY_FILE)%'
        jwt_kid: '%env(AUTH_JWT_KID)%'
    auth:
        issuer: 'https://app.example.com'
    database:
        dsn: '%env(POLARIS_DSN)%'                    # or service: doctrine.dbal.default_connection

# config/routes.yaml
polaris:
    resource: .
    type: polaris
```

```sh
bin/console polaris:schema:create   # the tables, the permission catalog, the system roles
bin/console polaris:doctor          # secrets, keys, manifest, database, schema
bin/console debug:router            # polaris.auth.login, ... under path_prefix
```

## Configure

| Key | Meaning |
| --- | --- |
| `path_prefix`, `manifest_directory` | Where the routes are mounted; the `api/**/*.yaml` directory (default: the one in `polaris/core`) |
| `secrets` | `app_key`, `jwt_private_key`, `jwt_public_key`, `jwt_kid`, the previous-key pair, each PEM also as `<key>_file`; or `service: id` for a `Polaris\Config\Secrets` service |
| `auth`, `rate_limits` | The `docs/auth/configuration.md` keys, or `{ service: id }` |
| `database` | `dsn`/`user`/`password`, or `service: id` (a PDO, a Doctrine DBAL connection, a Polaris adapter) |
| `cache`, `logger`, `dispatcher` | Service ids; defaults `cache.app` (PSR-6 pools are wrapped), `logger`, `event_dispatcher`. The cache holds rate limits, the denylist and OTP quotas, so it must outlive a request: a filesystem or Redis pool, never `cache.adapter.array` (Symfony resets it between requests) |
| `mailer`, `mail_from` | `log` (codes go to the log), `mail` (Symfony Mailer, plain text), or an `OtpMailerInterface` service |
| `sms` | `log`, or an `SmsSenderInterface` service |
| `breach_check`, `clock`, `encrypter`, `metrics`, `totp`, `qr_codes`, `rate_store` | Optional port services |

## Use

```yaml
# config/packages/security.yaml: your own routes behind Polaris access tokens
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            custom_authenticators: [Polaris\Symfony\Security\PolarisAuthenticator]
    access_control:
        - { path: ^/api, roles: ROLE_USER }
```

```php
$user = $security->getUser();     // Polaris\Symfony\Security\PolarisUser
$user->user->email;               // Polaris\Model\User
$user->claim('org');              // the active organization from the token
$user->getRoles();                // ROLE_USER plus ROLE_POLARIS_<ROLE> per organization role

// Polaris events are Symfony events
#[AsEventListener(Polaris\Event\UserRegistered::class)]

// The services
$graph = $container->get(Polaris\Wiring\Graph::class);
```

Console: `polaris:schema:create`, `polaris:schema:drop`, `polaris:schema:export`, `polaris:schema:diff`,
`polaris:manifest --format=json|openapi`, `polaris:doctor`.

The demo under [`examples/symfony`](https://github.com/univeros/polaris-core/tree/main/examples/symfony)
is a complete host in a dozen files.

## License

MIT.
