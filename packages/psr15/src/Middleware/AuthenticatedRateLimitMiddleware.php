<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Config\RateLimitConfig;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The per-user budget on every authenticated request.
 */
final class AuthenticatedRateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly RateLimitConfig $limits, private readonly RateLimiter $limiter)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$request->getAttribute(Attributes::TOKEN) instanceof TokenInterface) {
            return $handler->handle($request);
        }

        return $this->limiter->limit($this->limits->authenticated, KeyResolver::subject($request), $request, $handler);
    }
}
