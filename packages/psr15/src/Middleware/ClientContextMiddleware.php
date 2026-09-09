<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Http\Attributes;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_string;
use function mb_substr;
use function preg_replace;

/**
 * Records the client IP (from `REMOTE_ADDR` unless an adapter already set the attribute) and a
 * sanitised User-Agent for the audit log and rate-limit keys.
 */
final class ClientContextMiddleware implements MiddlewareInterface
{
    private const int MAX_LENGTH = 255;

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!is_string($request->getAttribute(Attributes::IP_ADDRESS))) {
            $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;
            if (is_string($remote) && $remote !== '') {
                $request = $request->withAttribute(Attributes::IP_ADDRESS, $remote);
            }
        }
        $userAgent = mb_substr((string) preg_replace('/[\x00-\x1F\x7F]/', '', $request->getHeaderLine('User-Agent')), 0, self::MAX_LENGTH);
        if ($userAgent !== '') {
            $request = $request->withAttribute(Attributes::USER_AGENT, $userAgent);
        }

        return $handler->handle($request);
    }
}
