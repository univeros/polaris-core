# polaris/psr15

The PSR-15 face of [Polaris for PHP](https://github.com/univeros/polaris-core): a router over
the endpoint manifest, the ordered middleware stack (client context, rate limits, bearer and
MFA-ticket authentication, step-up, denylist, authorization) and the request handler that runs
the endpoints. It works with any PSR-15 host: Slim, Mezzio, or a framework through its PSR-7
bridge.

## Install

```sh
composer require polaris/psr15
```

This brings `polaris/core`; you also need a PSR-17 response factory (`nyholm/psr7`,
`laminas/laminas-diactoros`, `slim/psr7`, ...).

## Use

```php
use Polaris\Psr15\Pipeline;

$pipeline = new Pipeline($polaris->graph(), $responseFactory, pathPrefix: '/');

$pipeline->middleware();      // list<MiddlewareInterface>, in execution order
$pipeline->handler();         // RequestHandlerInterface serving every route of the manifest
$pipeline->handle($request);  // or run the whole stack yourself
```

On Slim, for instance (the full demo is
[`examples/slim`](https://github.com/univeros/polaris-core/tree/main/examples/slim)):

```php
foreach (array_reverse($pipeline->middleware()) as $middleware) {   // Slim runs the last-added first
    $app->add($middleware);
}
$app->any('/{path:.*}', fn($request) => $pipeline->handler()->handle($request));
```

The middleware reads each route's policy (`auth`, `rate_limit`, `step_up`, required
permissions) from the manifest, so nothing is configured per route. Your own middleware can
read the request attributes named in `Polaris\Http\Attributes`: `TOKEN` (the verified token),
`IP_ADDRESS`, `USER_AGENT`.

## License

MIT.
