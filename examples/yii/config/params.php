<?php

declare(strict_types=1);

use PolarisDemo\FileMailer;
use Yiisoft\ErrorHandler\Middleware\ErrorCatcher;
use Yiisoft\Request\Body\RequestBodyParser;
use Yiisoft\Router\Middleware\Router;

// What differs from the package defaults (vendor/polaris/yii/config/params.php); the secrets come
// from .env (loaded by public/index.php and ./yii).
return [
    'polaris' => [
        'root_path' => dirname(__DIR__),
        'secrets' => [
            'app_key' => getenv('POLARIS_APP_KEY') ?: null,
            'jwt_private_key_file' => getenv('AUTH_JWT_PRIVATE_KEY_FILE') ?: null,
            'jwt_public_key_file' => getenv('AUTH_JWT_PUBLIC_KEY_FILE') ?: null,
            'jwt_kid' => getenv('AUTH_JWT_KID') ?: null,
        ],
        'auth' => ['issuer' => getenv('AUTH_ISSUER') ?: 'http://127.0.0.1:8080'],
        'database' => ['dsn' => 'sqlite:' . dirname(__DIR__) . '/var/polaris.sqlite'],
        // The demo mailbox (config/di.php); 'mail' would use the Yii mailer.
        'mailer' => FileMailer::class,
    ],
    'middlewares' => [ErrorCatcher::class, RequestBodyParser::class, Router::class],
];
