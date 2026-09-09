<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Exception\InvalidTokenException;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\MfaTicket;
use Polaris\Token\MfaLoginTokenService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * For routes whose spec says `auth: mfa_token`: the bearer must be a valid login-MFA ticket, which
 * becomes {@see Attributes::MFA_TICKET}.
 */
final class MfaTokenMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly MfaLoginTokenService $tickets,
        private readonly UnauthorizedResponder $unauthorized,
        private readonly BearerTokenExtractor $bearer = new BearerTokenExtractor(),
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || $spec->auth !== 'mfa_token') {
            return $handler->handle($request);
        }
        $token = $this->bearer->extract($request);
        if ($token === null) {
            return $this->unauthorized->respond();
        }
        try {
            $userId = $this->tickets->authenticate($token);
        } catch (InvalidTokenException) {
            return $this->unauthorized->respond();
        }

        return $handler->handle($request->withAttribute(Attributes::MFA_TICKET, new MfaTicket($userId)));
    }
}
