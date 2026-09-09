<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Polaris\Config\RateLimit;
use Polaris\Contract\RateStore;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function sprintf;

/**
 * Applies one {@see RateLimit} policy to a request keyed by `$key`, with the 1.0 response shape:
 * 429 with Retry-After when exhausted, X-RateLimit-* headers otherwise.
 */
final class RateLimiter
{
    public function __construct(
        private readonly RateStore $store,
        private readonly ClockInterface $clock,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {
    }

    public function limit(RateLimit $policy, string $key, ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $result = $this->store->hit(sprintf('%s.%s', $policy->keyPrefix, $key), $policy->limit, $policy->windowSeconds);
        if (!$result->allowed) {
            return $this->responseFactory->createResponse(429, 'Too Many Requests')
                ->withHeader('Retry-After', (string) $result->retryAfter($this->clock->now()->getTimestamp()))
                ->withHeader('X-RateLimit-Limit', (string) $result->limit)
                ->withHeader('X-RateLimit-Remaining', '0')
                ->withHeader('X-RateLimit-Reset', (string) $result->resetAt);
        }

        return $handler->handle($request)
            ->withHeader('X-RateLimit-Limit', (string) $result->limit)
            ->withHeader('X-RateLimit-Remaining', (string) $result->remaining)
            ->withHeader('X-RateLimit-Reset', (string) $result->resetAt);
    }
}
