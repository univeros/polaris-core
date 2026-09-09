<?php

declare(strict_types=1);

use Polaris\Config\EnvironmentConfig;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Wiring\Config;
use PolarisDemo\Dispatcher;
use PolarisDemo\Env;
use PolarisDemo\FileMailer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use Slim\Psr7\Factory\ResponseFactory;

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

Env::load($root);

$dsn = Env::require('POLARIS_DSN');
$pdo = new PDO(str_starts_with($dsn, 'sqlite:') ? 'sqlite:' . Env::sqlitePath($root, $dsn) : $dsn);
$pdo->exec('PRAGMA foreign_keys = ON');

$dispatcher = new Dispatcher();
$polaris = Polaris::create(new Config(
    secrets: EnvironmentConfig::secrets(),
    auth: EnvironmentConfig::auth(),
    database: new PdoAdapter($pdo),
    mailer: new FileMailer($root . '/var/mail.log'),
    dispatcher: $dispatcher,
));
foreach ($polaris->listeners() as $listener) {
    $dispatcher->listen($listener);
}

$pipeline = new Pipeline($polaris->graph(), new ResponseFactory());

$app = AppFactory::create();
$app->addBodyParsingMiddleware();
// Slim runs the last-added middleware first; Polaris lists its stack in execution order.
foreach (array_reverse($pipeline->middleware()) as $middleware) {
    $app->add($middleware);
}
$app->any('/{path:.*}', static fn(ServerRequestInterface $request): ResponseInterface => $pipeline->handler()->handle($request));

return $app;
