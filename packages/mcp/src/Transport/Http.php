<?php

declare(strict_types=1);

namespace Polaris\Mcp\Transport;

use Mcp\Server\Builder;
use Mcp\Server\Session\Psr16SessionStore;
use Mcp\Server\Transport\StatelessHttpTransport;
use Mcp\Server\Transport\StreamableHttpTransport;
use Polaris\Mcp\Protect\McpProtectedResource;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * The HTTP transport behind `POST /mcp`: with `legacy: reject` the SDK's stateless 2026-07-28 profile,
 * one JSON-RPC request per HTTP request and nothing kept between them; with `legacy: allow` the
 * streamable transport serving the 2025 handshake too, its sessions in the PSR-16 cache. The PSR-17
 * factories are passed explicitly, so the SDK never needs php-http/discovery; the SDK's browser
 * middleware (CORS, DNS-rebinding guards for localhost servers) stays off: Polaris sits behind a
 * host that owns those.
 */
final class Http
{
    private const int SESSION_TTL = 3600;

    public function __construct(
        private readonly ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
        private readonly CacheInterface $cache,
        private readonly string $legacy = McpProtectedResource::LEGACY_REJECT,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function handle(Builder $builder, ServerRequestInterface $request): ResponseInterface
    {
        if ($this->legacy === McpProtectedResource::LEGACY_ALLOW) {
            $builder->setSession(new Psr16SessionStore($this->cache, 'polaris.mcp.session.', self::SESSION_TTL));
            $transport = new StreamableHttpTransport($request, $this->responses, $this->streams, $this->logger, middleware: []);

            return $builder->build()->run($transport);
        }
        $transport = new StatelessHttpTransport($builder->buildStateless(), $this->responses, $this->streams, $this->logger ?? new NullLogger(), middleware: []);

        return $transport->handle($request);
    }
}
