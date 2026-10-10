<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function in_array;
use function parse_str;
use function str_starts_with;
use function strtolower;

/**
 * On the routes tagged `oauth`: a form body (`application/x-www-form-urlencoded`, what RFC 6749
 * clients send) is parsed when the host left it, and the parts of the request an endpoint cannot
 * read from its input are handed over as attributes: the `Authorization` header (HTTP Basic client
 * authentication), the `DPoP` header, and the method and URL (what a DPoP proof is bound to).
 */
final class OAuthRequestMiddleware implements MiddlewareInterface
{
    public const string TAG = 'oauth';
    public const string AUTHORIZATION = 'polaris.oauth.authorization';
    public const string DPOP = 'polaris.oauth.dpop';
    public const string METHOD = 'polaris.oauth.method';
    public const string URL = 'polaris.oauth.url';
    public const string ACCEPT = 'polaris.oauth.accept';

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || !in_array(self::TAG, $spec->tags, true)) {
            return $handler->handle($request);
        }
        $body = $request->getParsedBody();
        if (($body === null || $body === []) && str_starts_with(strtolower($request->getHeaderLine('Content-Type')), 'application/x-www-form-urlencoded')) {
            parse_str((string) $request->getBody(), $parsed);
            $request = $request->withParsedBody($parsed);
        }

        return $handler->handle($request
            ->withAttribute(self::AUTHORIZATION, $request->getHeaderLine('Authorization'))
            ->withAttribute(self::DPOP, $request->getHeaderLine('DPoP'))
            ->withAttribute(self::METHOD, $request->getMethod())
            ->withAttribute(self::URL, (string) $request->getUri())
            ->withAttribute(self::ACCEPT, $request->getHeaderLine('Accept')));
    }
}
