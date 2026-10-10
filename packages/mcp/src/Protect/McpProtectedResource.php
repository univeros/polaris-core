<?php

declare(strict_types=1);

namespace Polaris\Mcp\Protect;

use LogicException;
use Override;
use Polaris\Mcp\Jose;
use Polaris\Mcp\McpException;
use Polaris\Wiring\Graph;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\SimpleCache\CacheInterface;

use function array_diff;
use function array_filter;
use function array_keys;
use function array_values;
use function hash_equals;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function parse_url;
use function preg_match;
use function preg_split;
use function rtrim;
use function sprintf;
use function str_replace;
use function strlen;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const PHP_URL_PATH;

/**
 * PSR-15 middleware protecting an MCP server with Polaris-issued tokens, as RFC 9728 and the MCP
 * authorization profile have it: a request carries an access token for this resource (`Bearer`, or
 * `DPoP` with a proof when the token is bound), verified locally ({@see TokenVerifier}) and holding the
 * required scopes; without one it answers `401` with `WWW-Authenticate: Bearer resource_metadata="..."`
 * so a client finds the authorization server, with a bad one `error="invalid_token"`, short of a scope
 * `403 insufficient_scope` naming the missing scopes so the client steps up. It serves its own
 * metadata document at `/.well-known/oauth-protected-resource<path>` and, with `legacy: reject`,
 * refuses the 2025 session handshake. The verified claims reach the handler as {@see self::CLAIMS}.
 */
final class McpProtectedResource implements MiddlewareInterface
{
    public const string CLAIMS = 'polaris.mcp.claims';
    public const string LEGACY_REJECT = 'reject';
    public const string LEGACY_ALLOW = 'allow';
    public const string PROTOCOL_VERSION = '2026-07-28';
    public const string WELL_KNOWN = '/.well-known/oauth-protected-resource';
    private const int MAX_BODY_BYTES = 4194304;

    private readonly string $metadataUrl;
    /** @var list<string> */
    private readonly array $scopesSupported;

    /**
     * @param string $resource the MCP server's URL, the `aud` a token must name
     * @param list<string> $scopes the scopes every request must hold
     * @param string $legacy `reject` (the default) or `allow`: whether the 2025 session-based protocol is served
     * @param string|null $metadataUrl where the RFC 9728 document is served; by default the path-inserted well-known URL of the resource
     * @param list<string>|null $scopesSupported what the metadata advertises; the required scopes by default
     */
    public function __construct(
        private readonly string $resource,
        private readonly TokenVerifier $verifier,
        private readonly ResponseFactoryInterface $responses,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly array $scopes = [],
        private readonly string $legacy = self::LEGACY_REJECT,
        ?string $metadataUrl = null,
        private readonly ?string $resourceName = null,
        ?array $scopesSupported = null,
        private readonly ?StreamFactoryInterface $streams = null,
    ) {
        if (preg_match('~^https?://[^/\s]+~', $resource, $origin) !== 1) {
            throw new LogicException('resource must be an absolute http(s) URL.');
        }
        if (!in_array($legacy, [self::LEGACY_REJECT, self::LEGACY_ALLOW], true)) {
            throw new LogicException('legacy must be reject or allow.');
        }
        $this->metadataUrl = $metadataUrl ?? $origin[0] . self::WELL_KNOWN . rtrim((string) parse_url($resource, PHP_URL_PATH), '/');
        $this->scopesSupported = $scopesSupported ?? $scopes;
    }

    /**
     * Polaris's own `/mcp`: verified with core's signing keys (the current and, during a rotation, the
     * previous one), issued by core's issuer, for the resource or the issuer itself.
     *
     * @param list<string> $scopes
     * @param string $legacy `reject` or `allow`
     */
    public static function fromGraph(Graph $graph, string $resource, ResponseFactoryInterface $responses, array $scopes = [], string $legacy = self::LEGACY_REJECT, ?string $metadataUrl = null, ?string $resourceName = null, ?StreamFactoryInterface $streams = null): self
    {
        $secrets = $graph->config()->secrets;
        $issuer = $graph->config()->auth->issuer;
        $keys = [$secrets->jwtKid => $secrets->jwtPublicKey];
        if ($secrets->jwtPreviousKid !== null && $secrets->jwtPreviousPublicKey !== null) {
            $keys[$secrets->jwtPreviousKid] = $secrets->jwtPreviousPublicKey;
        }
        $verifier = TokenVerifier::withKeys($issuer, [$resource, $issuer], $keys, $graph->clock());
        $supported = array_values(array_filter(array_keys($graph->permissionCatalog()->permissions()), is_string(...)));

        return new self($resource, $verifier, $responses, $graph->cache(), $graph->clock(), $scopes, $legacy, $metadataUrl, $resourceName, [...$scopes, ...array_diff($supported, $scopes)], $streams);
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($request->getMethod() === 'GET' && $request->getUri()->getPath() === parse_url($this->metadataUrl, PHP_URL_PATH)) {
            return $this->json(200, $this->metadata(), ['Cache-Control' => 'public, max-age=3600']);
        }
        try {
            $request = $this->rejectLegacy($request);
            $claims = $this->authenticate($request);
        } catch (McpException $exception) {
            return $this->problem($exception);
        }

        return $handler->handle($request->withAttribute(self::CLAIMS, $claims));
    }

    /**
     * The RFC 9728 document.
     *
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        $document = [
            'resource' => $this->resource,
            'authorization_servers' => [$this->verifier->issuer()],
            'scopes_supported' => $this->scopesSupported,
            'bearer_methods_supported' => ['header'],
            'dpop_signing_alg_values_supported' => Jose::ALGORITHMS,
        ];
        if ($this->resourceName !== null) {
            $document['resource_name'] = $this->resourceName;
        }

        return $document;
    }

    public function metadataUrl(): string
    {
        return $this->metadataUrl;
    }

    /**
     * The claims of the token the request presents for this resource, bound as it must be and holding
     * the required scopes.
     *
     * @return array<string, mixed>
     * @throws McpException `unauthorized` (401), `insufficient_scope` (403)
     */
    public function authenticate(ServerRequestInterface $request): array
    {
        if (preg_match('/^(Bearer|DPoP)\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            throw new McpException(McpException::UNAUTHORIZED, 'An access token for this resource is required.', 401, ['WWW-Authenticate' => $this->challenge()]);
        }
        [, $scheme, $token] = $matches;
        try {
            $claims = $this->verifier->verify($token);
            $this->assertBinding($request, $scheme, $token, $claims);
        } catch (McpException $exception) {
            throw new McpException(McpException::UNAUTHORIZED, $exception->detail, 401, ['WWW-Authenticate' => $this->challenge('invalid_token', $exception->detail)]);
        }
        $missing = array_values(array_diff($this->scopes, self::scopes($claims)));
        if ($missing !== []) {
            $scope = implode(' ', $missing);
            throw new McpException(McpException::INSUFFICIENT_SCOPE, 'The token lacks the scopes ' . $scope . '.', 403, ['WWW-Authenticate' => $this->challenge('insufficient_scope', null, $scope)], ['missing_scopes' => $missing]);
        }

        return $claims;
    }

    public function problem(McpException $exception): ResponseInterface
    {
        return $this->json($exception->status, $exception->problem(), [...$exception->headers, 'Cache-Control' => 'no-store'], true);
    }

    /**
     * With `legacy: reject`, the 2025 handshake (a session header, an older protocol version, an
     * `initialize` call) is refused before any token is looked at: the answer tells the client which
     * revision to speak.
     *
     * @throws McpException `legacy_protocol`
     */
    private function rejectLegacy(ServerRequestInterface $request): ServerRequestInterface
    {
        if ($this->legacy === self::LEGACY_ALLOW) {
            return $request;
        }
        $version = $request->getHeaderLine('MCP-Protocol-Version');
        $legacy = $request->hasHeader('Mcp-Session-Id') || ($version !== '' && $version < self::PROTOCOL_VERSION);
        if (!$legacy && $request->getMethod() === 'POST') {
            [$request, $body] = $this->body($request);
            $decoded = $body === '' ? null : json_decode($body, true);
            $legacy = is_array($decoded) && ($decoded['method'] ?? null) === 'initialize';
        }
        if ($legacy) {
            throw new McpException(McpException::LEGACY_PROTOCOL, sprintf('This server speaks MCP %s (stateless); the session-based protocol is not served.', self::PROTOCOL_VERSION), 400, [], ['protocol_version' => self::PROTOCOL_VERSION]);
        }

        return $request;
    }

    /**
     * The request body, read once and bounded, left readable for the server behind.
     *
     * @return array{ServerRequestInterface, string}
     */
    private function body(ServerRequestInterface $request): array
    {
        $stream = $request->getBody();
        $body = '';
        while (!$stream->eof() && strlen($body) <= self::MAX_BODY_BYTES) {
            $chunk = $stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
        }
        if ($stream->isSeekable()) {
            $stream->rewind();
        } elseif ($this->streams !== null) {
            $request = $request->withBody($this->streams->createStream($body));
        }

        return [$request, strlen($body) > self::MAX_BODY_BYTES ? '' : $body];
    }

    /**
     * A bound token (`cnf.jkt`) is presented with the `DPoP` scheme and a proof for this request and
     * token, by the key it is bound to; a bearer token with the `Bearer` scheme.
     *
     * @param array<string, mixed> $claims
     * @throws McpException
     */
    private function assertBinding(ServerRequestInterface $request, string $scheme, string $token, array $claims): void
    {
        $cnf = $claims['cnf'] ?? null;
        $jkt = is_array($cnf) && is_string($cnf['jkt'] ?? null) ? $cnf['jkt'] : null;
        $dpopScheme = preg_match('/^dpop$/i', $scheme) === 1;
        if ($jkt === null) {
            if ($dpopScheme) {
                throw new McpException(McpException::UNAUTHORIZED, 'A bearer token is presented with the Bearer scheme.', 401);
            }

            return;
        }
        if (!$dpopScheme || !$request->hasHeader(DpopProof::HEADER)) {
            throw new McpException(McpException::UNAUTHORIZED, 'A DPoP-bound token is presented with the DPoP scheme and a proof.', 401);
        }
        $thumbprint = (new DpopProof($this->cache, $this->clock))->thumbprint($request->getHeaderLine(DpopProof::HEADER), $request->getMethod(), (string) $request->getUri(), $token);
        if (!hash_equals($jkt, $thumbprint)) {
            throw new McpException(McpException::UNAUTHORIZED, 'The DPoP proof is not for the key the token is bound to.', 401);
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @return list<string>
     */
    private static function scopes(array $claims): array
    {
        $scope = $claims['scope'] ?? null;
        if (is_array($scope)) {
            return array_values(array_filter($scope, is_string(...)));
        }

        return is_string($scope) ? array_values(array_filter(preg_split('/\s+/', $scope) ?: [], static fn(string $s): bool => $s !== '')) : [];
    }

    private function challenge(?string $error = null, ?string $description = null, ?string $scope = null): string
    {
        $parts = [];
        if ($error !== null) {
            $parts[] = sprintf('error="%s"', $error);
        }
        if ($description !== null) {
            $parts[] = sprintf('error_description="%s"', str_replace(['"', '\\'], '', $description));
        }
        if ($scope !== null) {
            $parts[] = sprintf('scope="%s"', $scope);
        }
        $parts[] = sprintf('resource_metadata="%s"', $this->metadataUrl);

        return 'Bearer ' . implode(', ', $parts);
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    private function json(int $status, array $body, array $headers = [], bool $problem = false): ResponseInterface
    {
        $response = $this->responses->createResponse($status)->withHeader('Content-Type', $problem ? 'application/problem+json' : 'application/json');
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        $response->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $response;
    }
}
