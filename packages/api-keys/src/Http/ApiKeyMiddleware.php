<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use Override;
use Polaris\Contract\RateStore;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_array;
use function is_int;
use function is_string;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * On a request an API key authenticated: a route gated by step-up is refused (a key cannot
 * re-authenticate, and a stolen key must not add credentials), and the key's own rate limit, when it
 * has one, is applied with the `X-RateLimit-*` headers core answers for its budgets.
 */
final class ApiKeyMiddleware implements MiddlewareInterface
{
    private const string LIMIT_PREFIX = 'api_keys.key';

    public function __construct(
        private readonly RateStore $rates,
        private readonly ClockInterface $clock,
        private readonly ResponseFactoryInterface $responses,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $request->getAttribute(Attributes::TOKEN);
        $keyId = $token instanceof TokenInterface ? $token->getMetadata(ApiKeyResolver::CLAIM) : null;
        if (!is_string($keyId) || $keyId === '') {
            return $handler->handle($request);
        }
        $spec = $request->getAttribute(Attributes::ROUTE);
        if ($spec instanceof EndpointSpec && $spec->stepUp) {
            return $this->problem(403, 'api-keys/not_allowed', 'Not allowed with an API key', 'This route requires a recent re-authentication, which an API key cannot provide.');
        }
        $limit = $token->getMetadata(ApiKeyResolver::RATE_LIMIT_CLAIM);
        if (!is_array($limit) || !is_int($limit['window'] ?? null) || !is_int($limit['max'] ?? null)) {
            return $handler->handle($request);
        }
        $result = $this->rates->hit(self::LIMIT_PREFIX . '.' . $keyId, $limit['max'], $limit['window']);
        if (!$result->allowed) {
            return $this->responses->createResponse(429, 'Too Many Requests')
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

    private function problem(int $status, string $type, string $title, string $detail): ResponseInterface
    {
        $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/problem+json');
        $response->getBody()->write(json_encode([
            'type' => Endpoint::PROBLEM_TYPES . $type,
            'title' => $title,
            'status' => $status,
            'detail' => $detail,
            'error' => 'api_keys_not_allowed',
            'message' => $detail,
        ], JSON_THROW_ON_ERROR));

        return $response;
    }
}
