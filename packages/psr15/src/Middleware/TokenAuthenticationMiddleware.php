<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Closure;
use Override;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Bearer authentication for every route whose spec says `auth: bearer`: the plugins' bearer
 * resolvers ({@see BearerResolver}) are asked first, in registration order; when none recognises the
 * request, the `Authorization: Bearer` token is parsed and verified by the Polaris token factory. The
 * token is stored as {@see Attributes::TOKEN}; a missing or invalid credential answers 401 with the
 * 1.0 envelope.
 */
final class TokenAuthenticationMiddleware implements MiddlewareInterface
{
    /** @var (Closure(): list<BearerResolver>)|null */
    private readonly ?Closure $resolvers;

    /**
     * @param (callable(): list<BearerResolver>)|null $resolvers the plugins' resolvers, built on the first request that needs them
     */
    public function __construct(
        private readonly TokenFactoryInterface $tokens,
        private readonly UnauthorizedResponder $unauthorized,
        private readonly BearerTokenExtractor $bearer = new BearerTokenExtractor(),
        ?callable $resolvers = null,
    ) {
        $this->resolvers = $resolvers === null ? null : $resolvers(...);
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || $spec->auth !== 'bearer') {
            return $handler->handle($request);
        }

        try {
            $parsed = $this->resolve($request);
        } catch (AuthorizationTokenException) {
            return $this->unauthorized->respond();
        }
        if ($parsed === null) {
            return $this->unauthorized->respond();
        }

        return $handler->handle($request->withAttribute(Attributes::TOKEN, $parsed));
    }

    /**
     * @throws AuthorizationTokenException
     */
    private function resolve(ServerRequestInterface $request): ?TokenInterface
    {
        foreach ($this->resolvers === null ? [] : ($this->resolvers)() as $resolver) {
            $token = $resolver->resolve($request);
            if ($token !== null) {
                return $token;
            }
        }
        $token = $this->bearer->extract($request);

        return $token === null ? null : $this->tokens->fromTokenString($token);
    }
}
