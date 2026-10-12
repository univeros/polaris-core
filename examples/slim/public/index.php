<?php

declare(strict_types=1);

// Under `php -S ... public/index.php` this is the router: a file of public/ is served by the built-in server
// itself, everything else is the application. Without a router, PHP 8.3's server answers its own 404 for a path
// under a dot directory (`/.well-known/agent-configuration`) instead of running index.php.
if (PHP_SAPI === 'cli-server' && is_file(__DIR__ . parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH))) {
    return false;
}

$app = require dirname(__DIR__) . '/src/bootstrap.php';
$app->run();
