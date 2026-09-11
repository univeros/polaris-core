<?php

declare(strict_types=1);

/*
 * Polaris for PHP. Every port takes null (the core default), a class name or container binding, or
 * an object. The `auth` and `rate_limits` keys are those of docs/auth/configuration.md; anything left
 * out keeps core's default.
 */
return [
    // Where the endpoints are mounted: `/auth/login` is served at `<path_prefix>/auth/login`.
    'path_prefix' => env('POLARIS_PATH_PREFIX', '/'),

    // Laravel middleware applied to the Polaris routes. None by default: Polaris brings its own stack
    // (client context, rate limits, authentication, step-up, denylist, authorization).
    'middleware' => [],

    'secrets' => [
        // At least 32 bytes; every Polaris key is HKDF-derived from it under its own context, so
        // Laravel's APP_KEY may double as it. A `<key>_file` entry reads the value from a file.
        'app_key' => env('POLARIS_APP_KEY', env('APP_KEY')),
        'jwt_private_key' => env('AUTH_JWT_PRIVATE_KEY'),
        'jwt_private_key_file' => env('AUTH_JWT_PRIVATE_KEY_FILE'),
        'jwt_public_key' => env('AUTH_JWT_PUBLIC_KEY'),
        'jwt_public_key_file' => env('AUTH_JWT_PUBLIC_KEY_FILE'),
        'jwt_kid' => env('AUTH_JWT_KID'),
        'jwt_previous_public_key' => env('AUTH_JWT_PREVIOUS_PUBLIC_KEY'),
        'jwt_previous_public_key_file' => env('AUTH_JWT_PREVIOUS_PUBLIC_KEY_FILE'),
        'jwt_previous_kid' => env('AUTH_JWT_PREVIOUS_KID'),
    ],

    'auth' => [
        'issuer' => env('AUTH_ISSUER', 'polaris'),
        'audience' => env('AUTH_AUDIENCE'),
        'access_token' => ['denylist' => env('AUTH_ACCESS_TOKEN_DENYLIST', false)],
        'password' => ['breach_check' => env('AUTH_PASSWORD_BREACH_CHECK', false)],
    ],
    'rate_limits' => [],

    // null: the default connection; a name: that connection; or a Polaris\Contract\DatabaseAdapter.
    'database' => env('POLARIS_DB_CONNECTION'),
    // null: the default cache store; a store name. Rate limits and the denylist live here.
    'cache' => env('POLARIS_CACHE_STORE'),
    // null: the default log channel; a channel name.
    'log' => env('POLARIS_LOG_CHANNEL'),
    // 'log': core's development driver (codes are written to the log, never delivered); 'mail':
    // Laravel's mailer with the polaris::mail.* views; or a Polaris\Contract\OtpMailerInterface.
    'mailer' => env('POLARIS_MAILER', 'log'),
    // 'log', or a Polaris\Contract\SmsSenderInterface.
    'sms' => env('POLARIS_SMS', 'log'),

    // Optional ports: null for the core default, or a class name, binding or object.
    'breach_check' => null,
    'clock' => null,
    'encrypter' => null,
    'metrics' => null,
    'totp' => null,
    'qr_codes' => null,
    'rate_store' => null,
    // A PSR-14 dispatcher of your own; null runs Laravel's events through Polaris\Laravel\Events\EventBridge.
    'dispatcher' => null,
    // The api/**/*.yaml directory; null for the one shipped with polaris/core.
    'manifest_directory' => null,
    // Plugins (Polaris\Contract\Plugin): class names, container bindings or instances; their tables,
    // routes, services, listeners and permissions join core's (docs/plugins/README.md).
    'plugins' => [],
];
