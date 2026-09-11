<?php

declare(strict_types=1);

use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;

/*
 * Polaris for PHP (docs/adapters/spec.md §3.1). The application overrides any key in its own params;
 * every port takes null (the core default) or a container id. The `auth` and `rate_limits` keys are
 * those of docs/auth/configuration.md.
 */
return [
    'polaris' => [
        // Relative `*_file` paths resolve against it; null means the working directory.
        'root_path' => null,
        // Where the endpoints are mounted.
        'path_prefix' => '/',
        // The api/**/*.yaml directory; null for the one shipped with polaris/core.
        'manifest_directory' => null,
        'secrets' => [
            'app_key' => null,
            'jwt_private_key' => null,
            'jwt_private_key_file' => null,
            'jwt_public_key' => null,
            'jwt_public_key_file' => null,
            'jwt_kid' => null,
            'jwt_previous_public_key' => null,
            'jwt_previous_public_key_file' => null,
            'jwt_previous_kid' => null,
        ],
        'auth' => [],
        'rate_limits' => [],
        // A DSN here, or a PDO / Yiisoft\Db connection / Polaris DatabaseAdapter definition in the container.
        'database' => ['dsn' => null, 'user' => null, 'password' => null],
        // 'log' (codes go to the log), 'mail' (the Yii mailer, plain text), or an OtpMailerInterface id.
        'mailer' => 'log',
        'mail_from' => null,
        // 'log', or an SmsSenderInterface id.
        'sms' => 'log',
        // Optional ports: null or a container id.
        'breach_check' => null,
        'clock' => null,
        'encrypter' => null,
        'metrics' => null,
        'totp' => null,
        'qr_codes' => null,
        'rate_store' => null,
        // Plugins (Polaris\Contract\Plugin): class names or container ids; their tables, routes,
        // services, listeners and permissions join core's (docs/plugins/README.md). For the route
        // table, an entry must be a class name (or an instance): routes are built from the params.
        'plugins' => [],
    ],
    'yiisoft/yii-console' => [
        'commands' => [
            'polaris:schema:export' => SchemaExportCommand::class,
            'polaris:schema:create' => SchemaCreateCommand::class,
            'polaris:schema:drop' => SchemaDropCommand::class,
            'polaris:schema:diff' => SchemaDiffCommand::class,
            'polaris:manifest' => ManifestCommand::class,
            'polaris:doctor' => DoctorCommand::class,
        ],
    ],
];
