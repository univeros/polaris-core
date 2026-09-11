<?php

declare(strict_types=1);

namespace Polaris\Admin\Http;

use Override;
use Polaris\Admin\Principal\Principals;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function in_array;
use function is_string;
use function str_starts_with;
use function substr;

/**
 * On the routes tagged `admin` (declared `auth: public`, so core's bearer middleware leaves API keys
 * alone), resolves the principal and attaches it to the request; the endpoints answer.
 */
final class AdminMiddleware implements MiddlewareInterface
{
    public const string TAG = 'admin';

    public function __construct(private readonly Principals $principals)
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
        $ip = $request->getAttribute(Attributes::IP_ADDRESS);
        $resolution = $this->principals->resolve($bearer, is_string($ip) ? $ip : null);

        return $handler->handle(
            $request->withAttribute(Principals::ATTRIBUTE, $resolution->principal)->withAttribute(Principals::IMPERSONATED, $resolution->impersonated),
        );
    }
}
