<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Bearer authentication for every route whose spec says `auth: bearer`: the token is parsed and
 * verified by the Polaris token factory and stored as {@see Attributes::TOKEN}; a missing or
 * invalid token answers 401 with the 1.0 envelope.
 */
final class TokenAuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly TokenFactoryInterface $tokens,
        private readonly UnauthorizedResponder $unauthorized,
        private readonly BearerTokenExtractor $bearer = new BearerTokenExtractor(),
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || $spec->auth !== 'bearer') {
            return $handler->handle($request);
        }

        $token = $this->bearer->extract($request);
        if ($token === null) {
            return $this->unauthorized->respond();
        }
        try {
            $parsed = $this->tokens->fromTokenString($token);
        } catch (AuthorizationTokenException) {
            return $this->unauthorized->respond();
        }

        return $handler->handle($request->withAttribute(Attributes::TOKEN, $parsed));
    }
}
