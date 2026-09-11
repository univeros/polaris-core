<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http;

use Override;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Decision;
use Polaris\Sentinel\Engine;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function bin2hex;
use function is_array;
use function is_string;
use function json_encode;
use function random_bytes;
use function sprintf;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * On the guarded routes, judges the attempt before the endpoint runs: a block answers `sentinel/blocked`,
 * a challenge `sentinel/challenge_required` (the client retries with a `captcha_token`) when a captcha
 * verifier is configured and the challenge band is recorded but let through when none is, anything else
 * goes through; in observe mode everything goes through. Sets the device cookie when the request has none.
 */
final class SentinelMiddleware implements MiddlewareInterface
{
    public const string COOKIE = 'polaris_device';
    public const array ROUTES = [
        '/auth/register' => Attempt::SIGN_UP,
        '/auth/login' => Attempt::SIGN_IN,
        '/auth/password/forgot' => Attempt::PASSWORD_RESET,
        '/auth/email/verify/resend' => Attempt::VERIFICATION_SEND,
        '/auth/mfa/challenge' => Attempt::OTP_SEND,
    ];
    private const int COOKIE_TTL = 31536000;

    /**
     * @param bool $challenges whether a challenge can be answered (a captcha verifier is configured)
     * @param array<string, string> $routes path => attempt kind
     */
    public function __construct(
        private readonly Engine $engine,
        private readonly ResponseFactoryInterface $responses,
        private readonly bool $challenges = false,
        private readonly array $routes = self::ROUTES,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        $kind = $spec instanceof EndpointSpec ? ($this->routes[$spec->path] ?? null) : null;
        if ($kind === null) {
            return $handler->handle($request);
        }
        $body = $request->getParsedBody();
        $body = is_array($body) ? $body : [];
        $cookie = $request->getCookieParams()[self::COOKIE] ?? null;
        $deviceId = is_string($cookie) && $cookie !== '' ? $cookie : null;
        $ip = $request->getAttribute(Attributes::IP_ADDRESS);
        $userAgent = $request->getAttribute(Attributes::USER_AGENT);
        $attempt = new Attempt(
            $kind,
            is_string($body['email'] ?? null) ? $body['email'] : null,
            is_string($ip) ? $ip : null,
            is_string($userAgent) ? $userAgent : null,
            $deviceId,
            is_string($body['captcha_token'] ?? null) ? $body['captcha_token'] : null,
            is_string($body['password'] ?? null) ? $body['password'] : null,
        );
        $decision = $this->engine->evaluate($attempt);
        if ($decision->enforced && $decision->action === Decision::BLOCK) {
            return $this->problem(403, 'sentinel/blocked', 'Blocked', 'The request was refused.');
        }
        if ($decision->enforced && $this->challenges && $decision->action === Decision::CHALLENGE) {
            return $this->problem(403, 'sentinel/challenge_required', 'Challenge required', 'Complete the challenge and try again.', ['challenge' => 'captcha']);
        }
        $response = $handler->handle($request);

        return $deviceId === null ? $this->withDeviceCookie($response, $request) : $response;
    }

    /**
     * @param array<string, mixed> $extensions
     */
    private function problem(int $status, string $type, string $title, string $detail, array $extensions = []): ResponseInterface
    {
        $body = [
            'type' => Endpoint::PROBLEM_TYPES . $type,
            'title' => $title,
            'status' => $status,
            'detail' => $detail,
            'error' => str_replace('/', '_', $type),
            'message' => $detail,
            ...$extensions,
        ];
        $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/problem+json');
        $response->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $response;
    }

    private function withDeviceCookie(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        $secure = $request->getUri()->getScheme() === 'https' ? '; Secure' : '';

        return $response->withAddedHeader('Set-Cookie', sprintf('%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s', self::COOKIE, bin2hex(random_bytes(16)), self::COOKIE_TTL, $secure));
    }
}
