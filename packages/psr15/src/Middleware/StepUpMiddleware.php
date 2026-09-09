<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Config\AuthConfig;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Mfa\MfaChallengeVerifier;
use Polaris\Psr15\JsonResponse;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_int;

/**
 * For routes whose spec says `step_up: true`: a user with a confirmed MFA factor must have
 * re-authenticated recently (`auth_time` within `security.step_up.max_age`).
 */
final class StepUpMiddleware implements MiddlewareInterface
{
    private const string STEP_UP_ENDPOINT = '/auth/mfa/step-up';

    public function __construct(
        private readonly MfaChallengeVerifier $verifier,
        private readonly AuthConfig $config,
        private readonly ClockInterface $clock,
        private readonly UnauthorizedResponder $unauthorized,
        private readonly JsonResponse $json,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || !$spec->stepUp) {
            return $handler->handle($request);
        }
        $token = $request->getAttribute(Attributes::TOKEN);
        if (!$token instanceof TokenInterface) {
            return $this->unauthorized->respond();
        }
        $userId = (string) $token->getMetadata('sub');
        if ($userId === '' || !$this->verifier->hasConfirmedFactor($userId) || $this->isRecent($token)) {
            return $handler->handle($request);
        }

        return $this->json->body(401, [
            'error' => 'step_up_required',
            'message' => 'This operation requires a recent re-authentication.',
            'step_up' => self::STEP_UP_ENDPOINT,
        ], ['WWW-Authenticate' => 'Bearer error="step_up_required"']);
    }

    private function isRecent(TokenInterface $token): bool
    {
        $authTime = $token->getMetadata('auth_time');

        return is_int($authTime) && ($this->clock->now()->getTimestamp() - $authTime) <= $this->config->stepUpMaxAge;
    }
}
