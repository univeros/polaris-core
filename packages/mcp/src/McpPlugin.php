<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use LogicException;
use Override;
use Polaris\Cli\CommandProvider;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Mcp\Console\McpCommand;
use Polaris\Mcp\Http\McpRequestMiddleware;
use Polaris\Mcp\Protect\McpProtectedResource;
use Polaris\Mcp\Server\Dispatcher;
use Polaris\Mcp\Server\ManifestTools;
use Polaris\Mcp\Server\McpServer;
use Polaris\Mcp\Transport\Http;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

use function dirname;
use function in_array;
use function preg_match;
use function rtrim;

/**
 * The MCP plugin: `new McpPlugin(baseUrl: 'https://app.example.com/auth', requests: $psr17, responses:
 * $psr17, streams: $psr17)` in `Config::$plugins`. Polaris as an MCP server at `POST /mcp` (protected as
 * an OAuth resource by {@see McpProtectedResource}, every route the caller may call as a tool) and over
 * stdio (`bin/polaris mcp`), with its RFC 9728 metadata at `/.well-known/oauth-protected-resource/mcp`.
 * `baseUrl` is where Polaris is mounted, prefix included: the resource is `<baseUrl>/mcp`, and the
 * tools dispatch their calls to the routes under it. No tables.
 */
final class McpPlugin extends AbstractPlugin implements BearerResolverProvider, CommandProvider
{
    public const string ID = 'mcp';
    public const string PATH = '/mcp';
    /** The request attribute carrying the principal of an in-process tool call (the resolved token). */
    public const string PRINCIPAL = 'polaris.mcp.principal';

    private readonly string $baseUrl;

    /**
     * @param list<string> $scopes the scopes a token must hold to reach `/mcp` at all (each tool call is then checked by its route)
     * @param string $legacy `reject` (the default) or `allow`: whether the 2025 session-based protocol is served
     */
    public function __construct(
        string $baseUrl,
        private readonly ServerRequestFactoryInterface $requests,
        private readonly ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
        private readonly array $scopes = [],
        private readonly string $legacy = McpProtectedResource::LEGACY_REJECT,
        private readonly string $serverName = 'Polaris',
        private readonly ?LoggerInterface $logger = null,
    ) {
        if (preg_match('~^https?://[^/\s]+~', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
        if (!in_array($legacy, [McpProtectedResource::LEGACY_REJECT, McpProtectedResource::LEGACY_ALLOW], true)) {
            throw new LogicException('legacy must be reject or allow.');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The mcp plugin is not registered.');
        }

        return $plugin;
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * The MCP server's URL, the resource a token must name.
     */
    public function resource(): string
    {
        return $this->baseUrl . self::PATH;
    }

    public function metadataUrl(): string
    {
        return $this->baseUrl . McpProtectedResource::WELL_KNOWN . self::PATH;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [
            McpProtectedResource::class => fn(Graph $graph): McpProtectedResource => McpProtectedResource::fromGraph($graph, $this->resource(), $this->responses, $this->scopes, $this->legacy, $this->metadataUrl(), $this->serverName, $this->streams),
            Principals::class => fn(Graph $graph): Principals => new Principals($graph, $this->requests, $this->resource()),
            Dispatcher::class => fn(Graph $graph): Dispatcher => new Dispatcher($graph, $this->requests, $this->responses, $this->streams, $this->baseUrl),
            ManifestTools::class => static fn(Graph $graph): ManifestTools => new ManifestTools($graph, $graph->get(Dispatcher::class)),
            McpServer::class => fn(Graph $graph): McpServer => new McpServer($graph, $graph->get(ManifestTools::class), $this->serverName, $this->logger),
            Http::class => fn(Graph $graph): Http => new Http($this->responses, $this->streams, $graph->cache(), $this->legacy, $this->logger),
        ];
    }

    #[Override]
    public function bearerResolvers(Graph $graph): array
    {
        return [new McpResolver()];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new McpRequestMiddleware()];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new McpCommand($graph->get(Principals::class), $graph->get(McpServer::class), $this->logger)];
    }
}
