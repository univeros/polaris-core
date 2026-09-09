<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Config\RateLimit;
use Polaris\Config\RateLimitConfig;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function lcfirst;
use function preg_replace_callback;
use function property_exists;
use function strtoupper;

/**
 * Per-IP budgets for the unauthenticated auth endpoints, by the spec's `rate_limit` group.
 */
final class AuthRateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly RateLimitConfig $limits, private readonly RateLimiter $limiter)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        $policy = $spec instanceof EndpointSpec ? $this->policy($spec) : null;
        if ($policy === null) {
            return $handler->handle($request);
        }

        return $this->limiter->limit($policy, KeyResolver::ip($request), $request, $handler);
    }

    private function policy(EndpointSpec $spec): ?RateLimit
    {
        if ($spec->rateLimit === null) {
            return null;
        }
        $property = lcfirst((string) preg_replace_callback('/_(\w)/', static fn(array $m): string => strtoupper($m[1]), $spec->rateLimit));

        return property_exists($this->limits, $property) && $this->limits->{$property} instanceof RateLimit ? $this->limits->{$property} : null;
    }
}
