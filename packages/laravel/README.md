# polaris/laravel

[Polaris for PHP](https://github.com/univeros/polaris-core) in a Laravel 13 application: a service
provider that builds Polaris from `config/polaris.php` on Laravel's database connection, cache, logger,
events and mailer; the 52 endpoints as Laravel routes; a `polaris` guard for your own routes; the
`polaris:*` artisan commands. Every response is the one the framework-free core sends: the whole
functional suite and the 184 contract fixtures replay through Laravel's HTTP kernel in CI.

## Install

```sh
composer require polaris/laravel
php artisan polaris:install     # publishes config/polaris.php, writes the migration
php artisan migrate             # the Polaris tables, the permission catalog, the system roles
```

Secrets come from the environment (`.env`):

```dotenv
POLARIS_APP_KEY=                      # optional: at least 32 bytes; defaults to Laravel's APP_KEY
AUTH_JWT_PRIVATE_KEY_FILE=storage/keys/private.pem
AUTH_JWT_PUBLIC_KEY_FILE=storage/keys/public.pem
AUTH_JWT_KID=key-1
AUTH_ISSUER=https://app.example.com
```

`php artisan polaris:doctor` checks them, the manifest and the database; `php artisan route:list` shows
the routes (`polaris.auth.login`, ...), mounted under `path_prefix` (`/` by default).

## Configure

`config/polaris.php` maps one to one to `Polaris\Wiring\Config`. Every port takes `null` (the core
default), a class name or container binding, or an object:

| Key | Meaning |
| --- | --- |
| `path_prefix`, `middleware` | Where the routes are mounted; Laravel middleware to add (none by default, Polaris brings its own stack) |
| `secrets` | `app_key`, `jwt_private_key`, `jwt_public_key`, `jwt_kid`, the previous-key pair; each also as `<key>_file` |
| `auth`, `rate_limits` | The `docs/auth/configuration.md` keys; anything left out keeps core's default |
| `database` | `null` (the default connection), a connection name, or a `DatabaseAdapter` |
| `cache`, `log` | A cache store / log channel name, or `null` for the defaults |
| `mailer` | `log` (codes go to the log), `mail` (Laravel's mailer with the `polaris::mail.*` views, `--tag=polaris-views` to publish), or an `OtpMailerInterface` |
| `sms` | `log`, or an `SmsSenderInterface` |
| `breach_check`, `clock`, `encrypter`, `metrics`, `totp`, `qr_codes`, `rate_store`, `dispatcher` | Optional ports |
| `plugins` | `Polaris\Contract\Plugin` class names, bindings or instances; their tables, routes, services, listeners and permissions join core's |

## Use

```php
// config/auth.php
'guards' => ['polaris' => ['driver' => 'polaris']],

// routes/api.php: your own routes behind Polaris access tokens
Route::middleware('auth:polaris')->get('/me/orders', function (Request $request) {
    $user = $request->user();          // Polaris\Laravel\Auth\PolarisUser
    $user->user->email;                // Polaris\Model\User
    $user->claim('org');               // the active organization from the token
});

// Polaris events are Laravel events
Event::listen(Polaris\Event\UserRegistered::class, fn ($event) => ...);

// The services
app(Polaris\Wiring\Graph::class)->organizations();
```

Artisan: `polaris:install`, `polaris:schema:export`, `polaris:schema:diff`, `polaris:manifest
--format=json|openapi`, `polaris:doctor`.

The demo under [`examples/laravel`](https://github.com/univeros/polaris-core/tree/main/examples/laravel)
is a complete host in a dozen files.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
