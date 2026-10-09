<?php

declare(strict_types=1);

use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\Config\EnvironmentConfig;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Social\SocialPlugin;
use Polaris\Support\CacheRateStore;
use Polaris\Support\InMemoryCache;
use Polaris\Support\SystemClock;
use Polaris\Wiring\Config;
use PolarisDemo\Dispatcher;
use PolarisDemo\Env;
use PolarisDemo\FakeProvider;
use PolarisDemo\FileCache;
use PolarisDemo\LoopbackClient;
use PolarisDemo\FileMailer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use Slim\Psr7\Factory\RequestFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\StreamFactory;

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

Env::load($root);

$dsn = Env::require('POLARIS_DSN');
$pdo = new PDO(str_starts_with($dsn, 'sqlite:') ? 'sqlite:' . Env::sqlitePath($root, $dsn) : $dsn);
$pdo->exec('PRAGMA foreign_keys = ON');

$dispatcher = new Dispatcher();
// localhost, not 127.0.0.1: a passkey's relying party id must be a domain.
$baseUrl = rtrim((string) (getenv('POLARIS_BASE_URL') ?: 'http://localhost:8080'), '/');
$app = AppFactory::create();
$app->addBodyParsingMiddleware();
// The demo's own OAuth 2 server and mailbox, outside Polaris's routes.
FakeProvider::register($app, $root);
$polaris = Polaris::create(new Config(
    secrets: EnvironmentConfig::secrets(),
    auth: EnvironmentConfig::auth(),
    database: new PdoAdapter($pdo),
    mailer: new FileMailer($root . '/var/mail.log'),
    // php -S runs every request in a fresh process: the plugins' short-lived state (OAuth states, passkey
    // challenges, hand-off codes) goes to files; the rate limits stay in memory, so the demo never locks itself out.
    cache: new FileCache($root . '/var/cache'),
    rateStore: new CacheRateStore(new InMemoryCache(), new SystemClock()),
    dispatcher: $dispatcher,
    plugins: [
        new AuditPlugin(),
        new AdminPlugin(),
        // Social sign-in through the fake provider (add real ones with their client ids and secrets).
        new SocialPlugin(
            baseUrl: $baseUrl,
            providers: ['fake' => ['client_id' => 'demo', 'client_secret' => 'demo', 'definition' => FakeProvider::definition($baseUrl)]],
            httpClient: new LoopbackClient($app),
            requestFactory: new RequestFactory(),
            streamFactory: new StreamFactory(),
            redirectUris: [$baseUrl . '/signed-in'],
        ),
        new PasskeyPlugin(origins: [$baseUrl], rpName: 'Polaris demo'),
    ],
));
foreach ($polaris->listeners() as $listener) {
    $dispatcher->listen($listener);
}
$pipeline = new Pipeline($polaris->graph(), new ResponseFactory());
// Polaris's stack runs on its own routes only (the fake provider's static routes match first). Slim
// runs the last-added middleware first; Polaris lists its stack in execution order.
$route = $app->any('/{path:.*}', static fn(ServerRequestInterface $request): ResponseInterface => $pipeline->handler()->handle($request));
foreach (array_reverse($pipeline->middleware()) as $middleware) {
    $route->add($middleware);
}

return $app;
