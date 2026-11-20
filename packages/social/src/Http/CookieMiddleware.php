<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Hands the request's own cookies to the social endpoints as a request attribute: endpoint input merges
 * cookies under the query and the body, so a value there could pass for the flow's binding cookie.
 */
final class CookieMiddleware implements MiddlewareInterface
{
    public const string ATTRIBUTE = 'polaris.social.cookies';

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $handler->handle($request->withAttribute(self::ATTRIBUTE, $request->getCookieParams()));
    }
}
