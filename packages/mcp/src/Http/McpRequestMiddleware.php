<?php

declare(strict_types=1);

namespace Polaris\Mcp\Http;

use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function in_array;

/**
 * On the routes tagged `mcp`: the PSR-7 request itself is handed to the endpoint as an attribute,
 * because the MCP transport needs the whole message (the JSON-RPC body, the protocol headers, the
 * `Authorization` and `DPoP` headers a proof is bound to), not the parsed input an endpoint reads.
 */
final class McpRequestMiddleware implements MiddlewareInterface
{
    public const string TAG = 'mcp';
    public const string REQUEST = 'polaris.mcp.request';

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || !in_array(self::TAG, $spec->tags, true)) {
            return $handler->handle($request);
        }

        return $handler->handle($request->withAttribute(self::REQUEST, $request));
    }
}
