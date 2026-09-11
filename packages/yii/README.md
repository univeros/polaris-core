# polaris/yii

[Polaris for PHP](https://github.com/univeros/polaris-core) in a Yii 3 application: a `yiisoft/config`
plugin whose `polaris` params become the `Config`, `Polaris`, `Graph` and `Pipeline` definitions on the
application's connection, cache, logger, event dispatcher and mailer; the 52 endpoints as routes in the
`routes` group; an authentication method for your own routes; the `polaris:*` console commands. Every
response is the one the framework-free core sends: the whole functional suite and the 184 contract
fixtures replay through the Yii application in CI.

## Install

```sh
composer require polaris/yii
```

With `yiisoft/config` the package's groups merge into the application (`params`, `di`, `di-console`,
`routes`, `events-web`, `events-console`); the application's own `config/params.php` sets what differs:

```php
'polaris' => [
    'root_path' => dirname(__DIR__),
    'secrets' => [
        'app_key' => getenv('POLARIS_APP_KEY'),                       // at least 32 bytes
        'jwt_private_key_file' => 'var/keys/private.pem',             // relative to root_path
        'jwt_public_key_file' => 'var/keys/public.pem',
        'jwt_kid' => 'key-1',
    ],
    'auth' => ['issuer' => 'https://app.example.com'],
    'database' => ['dsn' => 'sqlite:' . dirname(__DIR__) . '/var/polaris.sqlite'],   // or a PDO / Yiisoft\Db connection definition
],
```

```sh
./yii polaris:schema:create   # the tables, the permission catalog, the system roles
./yii polaris:doctor          # secrets, keys, manifest, database, schema
```

The application provides what every Yii application has: PSR-17 factories, `Psr\SimpleCache\CacheInterface`
(rate limits, the denylist and OTP quotas live there, so a cache that outlives a request), a PSR-3 logger,
`yiisoft/yii-event` (the Polaris listeners are registered on every Polaris event class), and a
`RouteCollectionInterface` built from the `routes` group.

## Configure

| Key | Meaning |
| --- | --- |
| `root_path`, `path_prefix`, `manifest_directory` | Where relative PEM paths resolve; where the routes are mounted; the `api/**/*.yaml` directory |
| `secrets` | `app_key`, `jwt_private_key`, `jwt_public_key`, `jwt_kid`, the previous-key pair, each PEM also as `<key>_file` |
| `auth`, `rate_limits` | The `docs/auth/configuration.md` keys; anything left out keeps core's default |
| `database` | `dsn`/`user`/`password`, or leave the DSN null and define `PDO`, a `Yiisoft\Db` connection or a `DatabaseAdapter` in the container |
| `mailer`, `mail_from` | `log` (codes go to the log), `mail` (the Yii mailer, plain text), or an `OtpMailerInterface` id |
| `sms` | `log`, or an `SmsSenderInterface` id |
| `breach_check`, `clock`, `encrypter`, `metrics`, `totp`, `qr_codes`, `rate_store` | Optional port ids |
| `plugins` | `Polaris\Contract\Plugin` class names (the route table is built from the params) or container ids; their tables, routes, services, listeners and permissions join core's |

## Use

```php
// config/routes.php: your own routes behind Polaris access tokens
Route::get('/app/me')->middleware('polaris/authentication')->action(MeAction::class),

// in the action: the identity yiisoft/auth stored on the request
$identity = $request->getAttribute(Yiisoft\Auth\Middleware\Authentication::class);   // Polaris\Yii\Auth\PolarisIdentity
$identity->user->email;                                                               // Polaris\Model\User
$identity->claim('org');                                                              // the active organization from the token

// The services
$graph = $container->get(Polaris\Wiring\Graph::class);
```

Console: `polaris:schema:create`, `polaris:schema:drop`, `polaris:schema:export`, `polaris:schema:diff`,
`polaris:manifest --format=json|openapi`, `polaris:doctor`.

The demo under [`examples/yii`](https://github.com/univeros/polaris-core/tree/main/examples/yii) is a
complete host in a dozen files.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
