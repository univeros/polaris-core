<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests\Support;

use Closure;
use Laminas\Diactoros\ServerRequestFactory;
use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function is_array;
use function json_decode;
use function parse_str;
use function str_contains;

/**
 * A PSR-18 client that handles the request in-process through the functional harness (the PSR-15
 * pipeline): the SDK talks to the server exactly as it would over HTTP, body bytes included (the
 * request JWT's `body_hash` covers them), with the JSON body parsed as a host's body parser would.
 */
final class PipelineClient implements ClientInterface
{
    /**
     * @param Closure(ServerRequestInterface): ResponseInterface $handle
     */
    public function __construct(private readonly Closure $handle)
    {
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $server = (new ServerRequestFactory())->createServerRequest($request->getMethod(), $request->getUri());
        foreach ($request->getHeaders() as $name => $values) {
            $server = $server->withHeader($name, $values);
        }
        parse_str($request->getUri()->getQuery(), $query);
        $server = $server->withQueryParams($query)->withBody($request->getBody());
        if (str_contains($request->getHeaderLine('Content-Type'), 'application/json')) {
            $decoded = json_decode((string) $request->getBody(), true);
            $request->getBody()->rewind();
            $server = $server->withParsedBody(is_array($decoded) ? $decoded : null);
        }

        return ($this->handle)($server);
    }
}
