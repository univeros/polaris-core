<?php

declare(strict_types=1);

namespace Polaris\Scim\Http;

use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Scim\Connections;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function in_array;
use function str_starts_with;
use function substr;

/**
 * On the routes tagged `scim` (declared `auth: public`, so core's bearer middleware leaves the
 * connection tokens alone), resolves the bearer to its active connection and attaches it; the endpoints
 * check it is the path's and answer.
 */
final class ScimMiddleware implements MiddlewareInterface
{
    public const string TAG = 'scim';
    public const string ATTRIBUTE = 'polaris.scim.connection';

    public function __construct(private readonly Connections $connections)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || !in_array(self::TAG, $spec->tags, true)) {
            return $handler->handle($request);
        }
        $header = $request->getHeaderLine('Authorization');
        $bearer = str_starts_with($header, 'Bearer ') ? substr($header, 7) : null;

        return $handler->handle($request->withAttribute(self::ATTRIBUTE, $this->connections->authenticate($bearer)));
    }
}
