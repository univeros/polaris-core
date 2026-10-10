<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Mcp\McpPlugin;
use Polaris\Mcp\Principal;
use Polaris\Psr15\Pipeline;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function http_build_query;
use function in_array;
use function is_scalar;
use function json_decode;
use function json_encode;
use function parse_url;
use function preg_match_all;
use function rawurlencode;
use function rtrim;
use function str_replace;

use const JSON_THROW_ON_ERROR;
use const PHP_URL_PATH;

/**
 * Runs a tool call as the HTTP route would run: an in-process PSR-7 request to the route's URL under
 * `baseUrl` (path parameters substituted, the rest as the query or the JSON body), through the whole
 * `Polaris\Psr15\Pipeline` (rate limits, step-up, denylist, authorization, every plugin's middleware),
 * so the tool answers exactly what the route answers. The principal rides as the request attribute
 * {@see McpPlugin::PRINCIPAL} that the mcp plugin's bearer resolver returns; the admin plugin's routes
 * authenticate from the `Authorization` header alone (an operator key or a session, never a bound
 * token), so they alone get the credential re-sent.
 */
final class Dispatcher
{
    private const string ADMIN_TAG = 'admin';

    private readonly Pipeline $pipeline;
    private readonly string $baseUrl;

    public function __construct(
        Graph $graph,
        private readonly ServerRequestFactoryInterface $requests,
        ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
        string $baseUrl,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $path = (string) parse_url($this->baseUrl, PHP_URL_PATH);
        $this->pipeline = new Pipeline($graph, $responses, $path === '' ? '/' : $path);
    }

    /**
     * @param array<string, mixed> $arguments
     * @return array{status: int, body: mixed}
     */
    public function call(EndpointSpec $spec, array $arguments, Principal $principal): array
    {
        preg_match_all('/\{(\w+)\}/', $spec->path, $matches);
        $path = $spec->path;
        foreach ($matches[1] as $name) {
            $value = $arguments[$name] ?? '';
            $path = str_replace('{' . $name . '}', rawurlencode(is_scalar($value) ? (string) $value : ''), $path);
            unset($arguments[$name]);
        }
        $query = $spec->inputSource === 'query' ? $arguments : [];
        $body = $spec->inputSource === 'body' ? $arguments : [];
        $url = $this->baseUrl . $path . ($query === [] ? '' : '?' . http_build_query($query));
        $request = $this->requests->createServerRequest($spec->method, $url)
            ->withHeader('Accept', 'application/json')
            ->withQueryParams($query);
        if ($body !== []) {
            $request = $request
                ->withHeader('Content-Type', 'application/json')
                ->withParsedBody($body)
                ->withBody($this->streams->createStream(json_encode($body, JSON_THROW_ON_ERROR)));
        }
        if ($principal->token !== null) {
            $request = $request->withAttribute(McpPlugin::PRINCIPAL, $principal->token);
        }
        if ($principal->credential !== null && in_array(self::ADMIN_TAG, $spec->tags, true)) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $principal->credential);
        }
        $response = $this->pipeline->handle($request);
        $raw = (string) $response->getBody();
        $decoded = $raw === '' ? null : json_decode($raw, true);

        return ['status' => $response->getStatusCode(), 'body' => $raw === '' ? null : ($decoded ?? $raw)];
    }
}
