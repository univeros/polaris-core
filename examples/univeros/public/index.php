<?php

declare(strict_types=1);

use Altair\Container\Container;
use Altair\Http\Middleware\ActionMiddleware;
use Altair\Http\Middleware\DispatcherMiddleware;
use Altair\Http\Middleware\ExceptionHandlerMiddleware;
use Altair\Http\Support\ModuleRoutes;
use Altair\Http\Support\ProblemDetailsErrorHandler;
use FastRoute\RouteCollector;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PolarisDemo\Env;
use PolarisDemo\PolarisMiddleware;
use Relay\Relay;

use function FastRoute\simpleDispatcher;

require dirname(__DIR__) . '/vendor/autoload.php';

Env::load(dirname(__DIR__));

/** @var Container $container */
$container = require dirname(__DIR__) . '/config/container.php';

/** @var list<array{0: string, 1: string, 2: class-string}> $routes */
$routes = require dirname(__DIR__) . '/config/routes.php';
$routes = ModuleRoutes::collect($container, $routes);

$dispatcher = simpleDispatcher(static function (RouteCollector $collector) use ($routes, $container): void {
    foreach ($routes as [$method, $path, $action]) {
        $collector->addRoute($method, $path, $container->make($action));
    }
});

$debug = filter_var($_SERVER['APP_DEBUG'] ?? getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOL);

// The Univeros skeleton's pipeline, with the Polaris middleware first: Polaris routes never reach
// FastRoute, and they stay outside ExceptionHandlerMiddleware, which turns every error response into
// problem+json; Polaris answers its own 4xx envelopes.
$relay = new Relay([
    $container->get(PolarisMiddleware::class),
    new ExceptionHandlerMiddleware(
        responseFactory: new ResponseFactory(),
        handler: new ProblemDetailsErrorHandler(debug: $debug),
        capture: true,
    ),
    new DispatcherMiddleware($dispatcher),
    new ActionMiddleware(
        static fn(string $class): object => $container->make($class),
        new ResponseFactory(),
    ),
]);

$response = $relay->handle(ServerRequestFactory::fromGlobals());

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header(sprintf('%s: %s', $name, $value), false);
    }
}
echo $response->getBody();
