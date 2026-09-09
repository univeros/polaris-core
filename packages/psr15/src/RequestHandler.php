<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Closure;
use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_array;

/**
 * The end of the pipeline: routes by the manifest when {@see RouteMiddleware} has not already,
 * builds the {@see Input}, invokes the endpoint the resolver returns for the spec's class, and
 * renders the {@see \Polaris\Http\Result}.
 */
final class RequestHandler implements RequestHandlerInterface
{
    /** @var Closure(class-string): Endpoint */
    private readonly Closure $resolver;

    /**
     * @param callable(class-string): Endpoint $resolver
     */
    public function __construct(
        private readonly Router $router,
        callable $resolver,
        private readonly JsonResponse $json,
    ) {
        $this->resolver = $resolver(...);
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        $params = $request->getAttribute(Attributes::ROUTE_PARAMS);
        if (!$spec instanceof EndpointSpec) {
            $match = $this->router->match($request->getMethod(), $request->getUri()->getPath());
            if ($match->spec === null) {
                return $match->allowedMethods !== []
                    ? $this->json->error(405, 'method_not_allowed', 'The method is not allowed for this endpoint.')
                    : $this->json->error(404, 'not_found', 'No such endpoint.');
            }
            $spec = $match->spec;
            $params = $match->params;
        }

        $endpoint = ($this->resolver)($spec->class);
        $input = Input::fromServerRequest($request, is_array($params) ? $params : []);

        return $this->json->result($endpoint($input));
    }
}
