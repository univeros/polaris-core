<?php

declare(strict_types=1);

namespace PolarisDemo;

use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Slim\App;
use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * A PSR-18 client that handles the request in this process: the fake provider lives in the same Slim
 * application, and `php -S` serves one request at a time, so a real HTTP call to it would wait forever.
 */
final class LoopbackClient implements ClientInterface
{
    /**
     * @param App<\Psr\Container\ContainerInterface|null> $app
     */
    public function __construct(private readonly App $app)
    {
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $server = (new ServerRequestFactory())->createServerRequest($request->getMethod(), $request->getUri());
        foreach ($request->getHeaders() as $name => $values) {
            $server = $server->withHeader($name, $values);
        }

        return $this->app->handle($server->withBody($request->getBody()));
    }
}
