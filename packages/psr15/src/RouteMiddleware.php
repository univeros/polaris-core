<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Override;
use Polaris\Http\Attributes;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function implode;

/**
 * First in the stack: resolves the manifest route so the middleware behind it can read the
 * endpoint's policy (`auth`, `rate_limit`, `step_up`, required permissions). Unknown routes
 * answer 404 and wrong methods 405 in the error envelope.
 */
final class RouteMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly Router $router, private readonly JsonResponse $json)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $match = $this->router->match($request->getMethod(), $request->getUri()->getPath());
        if ($match->spec === null) {
            if ($match->allowedMethods !== []) {
                return $this->json->error(405, 'method_not_allowed', 'The method is not allowed for this endpoint.', ['Allow' => implode(', ', $match->allowedMethods)]);
            }

            return $this->json->error(404, 'not_found', 'No such endpoint.');
        }

        return $handler->handle(
            $request->withAttribute(Attributes::ROUTE, $match->spec)->withAttribute(Attributes::ROUTE_PARAMS, $match->params),
        );
    }
}
