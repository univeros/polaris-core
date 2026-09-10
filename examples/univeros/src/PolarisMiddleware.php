<?php

declare(strict_types=1);

namespace PolarisDemo;

use Override;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_array;
use function json_decode;
use function str_contains;

/**
 * Serves the Polaris routes: a request whose path is in the manifest runs through the whole
 * Polaris middleware stack and handler (a wrong method included, Polaris answers its 405); any
 * other path continues to the Univeros dispatcher. A JSON body the framework has not parsed yet
 * is parsed here, as Slim's body parser would.
 */
final readonly class PolarisMiddleware implements MiddlewareInterface
{
    public function __construct(private Router $router, private Pipeline $pipeline)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $match = $this->router->match($request->getMethod(), $request->getUri()->getPath());
        if ($match->spec === null && $match->allowedMethods === []) {
            return $handler->handle($request);
        }

        return $this->pipeline->handle(self::withJsonBody($request));
    }

    private static function withJsonBody(ServerRequestInterface $request): ServerRequestInterface
    {
        // ServerRequestFactory::fromGlobals() hands $_POST over as the parsed body: an empty array for a JSON request.
        $parsed = $request->getParsedBody();
        if (($parsed !== null && $parsed !== []) || !str_contains($request->getHeaderLine('Content-Type'), 'json')) {
            return $request;
        }
        $body = (string) $request->getBody();
        $decoded = $body === '' ? null : json_decode($body, true);

        return is_array($decoded) ? $request->withParsedBody($decoded) : $request;
    }
}
