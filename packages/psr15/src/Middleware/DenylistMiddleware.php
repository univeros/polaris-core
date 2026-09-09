<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use DateTimeImmutable;
use Override;
use Polaris\Config\AuthConfig;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Psr15\JsonResponse;
use Polaris\Token\AccessTokenDenylist;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Rejects access tokens issued before the user's last logout-everywhere, when the denylist is on.
 */
final class DenylistMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly AccessTokenDenylist $denylist,
        private readonly AuthConfig $config,
        private readonly JsonResponse $json,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->config->accessToken->denylist) {
            return $handler->handle($request);
        }
        $token = $request->getAttribute(Attributes::TOKEN);
        if (!$token instanceof TokenInterface) {
            return $handler->handle($request);
        }
        $userId = (string) $token->getMetadata('sub');
        $issuedAt = $token->getMetadata('iat');
        if ($userId === '' || !$issuedAt instanceof DateTimeImmutable || $this->denylist->isRevoked($userId, $issuedAt)) {
            return $this->json->error(401, 'session_ended', 'The session is no longer active.');
        }

        return $handler->handle($request);
    }
}
