<?php

declare(strict_types=1);

use PolarisDemo\FileMailer;

// Overrides of the package defaults (vendor/polaris/laravel/config/polaris.php); everything else,
// secrets included, comes from .env.
return [
    'auth' => [
        'issuer' => env('AUTH_ISSUER', 'http://127.0.0.1:8080'),
    ],
    'mailer' => FileMailer::class,
];
