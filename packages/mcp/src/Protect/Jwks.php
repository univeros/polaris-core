<?php

declare(strict_types=1);

namespace Polaris\Mcp\Protect;

use Polaris\Mcp\McpException;
use Polaris\Support\SystemClock;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;

use function hash;
use function is_array;
use function is_int;
use function json_decode;
use function str_starts_with;
use function strlen;

/**
 * A remote issuer's JWK Set, fetched from the configured `jwksUri` alone (never a URL a token names)
 * over the host's PSR-18 client, bounded in size and cached in the PSR-16 cache; an unknown `kid`
 * fetches it once more, which is how a key rotation reaches a resource server, at most once a minute:
 * an unauthenticated JWT naming any `kid` must not make the resource server call the issuer.
 */
final class Jwks
{
    public const int MIN_REFETCH_INTERVAL = 60;
    private const int MAX_BYTES = 65536;
    private const string CACHE_PREFIX = 'polaris.mcp.jwks.';

    public function __construct(
        private readonly string $uri,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly CacheInterface $cache,
        private readonly int $ttl = 3600,
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
        if (!str_starts_with($uri, 'https://')) {
            throw new \LogicException('jwksUri must be an https URL.');
        }
    }

    /**
     * The key set, cached; `$fresh` asks for a refetch (an unknown kid), granted once per
     * `MIN_REFETCH_INTERVAL` (the attempt is remembered in the cache whether or not the issuer answered);
     * meanwhile the cached set, in which the kid stays unknown.
     *
     * @return array{keys: list<array<string, mixed>>}
     * @throws McpException `unauthorized`
     */
    public function keys(bool $fresh = false): array
    {
        $key = self::CACHE_PREFIX . hash('sha256', $this->uri);
        $cached = $this->cache->get($key);
        if (is_array($cached) && isset($cached['keys'])) {
            /** @var array{keys: list<array<string, mixed>>} $cached */
            if (!$fresh) {
                return $cached;
            }
            $now = $this->clock->now()->getTimestamp();
            $refetched = $this->cache->get($key . '.refetched');
            if (is_int($refetched) && $now - $refetched < self::MIN_REFETCH_INTERVAL) {
                return $cached;
            }
            $this->cache->set($key . '.refetched', $now, self::MIN_REFETCH_INTERVAL);
        }
        $set = $this->fetch();
        $this->cache->set($key, $set, $this->ttl);

        return $set;
    }

    /**
     * @return array{keys: list<array<string, mixed>>}
     */
    private function fetch(): array
    {
        try {
            $response = $this->http->sendRequest($this->requests->createRequest('GET', $this->uri)->withHeader('Accept', 'application/json'));
        } catch (ClientExceptionInterface) {
            // The reason stays on the server: a client is told only that the token could not be verified.
            throw $this->unavailable();
        }
        $stream = $response->getBody();
        $body = '';
        while (!$stream->eof() && strlen($body) <= self::MAX_BYTES) {
            $chunk = $stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
        }
        $decoded = $response->getStatusCode() === 200 && strlen($body) <= self::MAX_BYTES ? json_decode($body, true) : null;
        if (!is_array($decoded) || !is_array($decoded['keys'] ?? null)) {
            throw $this->unavailable();
        }
        $keys = [];
        foreach ($decoded['keys'] as $jwk) {
            if (is_array($jwk)) {
                $keys[] = $jwk;
            }
        }

        return ['keys' => $keys];
    }

    private function unavailable(): McpException
    {
        return new McpException(McpException::UNAUTHORIZED, 'The token could not be verified against the issuer\'s keys.', 401);
    }
}
