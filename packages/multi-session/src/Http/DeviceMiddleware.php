<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Override;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\MultiSession\Devices;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;
use function sprintf;
use function str_contains;

/**
 * Tracks the device on every Polaris route: the device id the request carries (the `X-Polaris-Device`
 * header, or the HttpOnly cookie) is accepted when the server minted it, and handed to the endpoints as
 * a request attribute; a response that carries a new token pair (any sign-in method, a refresh, a
 * switch) is recorded against the device, minting one when the request had none, and answers its id
 * (a new one after a sign-in that joined the device).
 */
final class DeviceMiddleware implements MiddlewareInterface
{
    public const string HEADER = 'X-Polaris-Device';
    public const string COOKIE = 'polaris_ms_device';
    public const string ATTRIBUTE = 'polaris.multi_session.device';
    private const int COOKIE_TTL = 31536000;

    public function __construct(private readonly Devices $devices, private readonly TokenFactoryInterface $tokens, private readonly bool $cookie = true)
    {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $presented = $request->getHeaderLine(self::HEADER);
        if ($presented === '') {
            $cookie = $request->getCookieParams()[self::COOKIE] ?? null;
            $presented = is_string($cookie) ? $cookie : '';
        }
        $deviceId = $presented !== '' && $this->devices->known($presented) ? $presented : null;
        $response = $handler->handle($request->withAttribute(self::ATTRIBUTE, $deviceId));
        $session = $this->session($response);
        if ($session === null) {
            return $response;
        }
        $deviceId = $this->devices->record($deviceId ?? Devices::mint(), ...$session);
        $response = $response->withHeader(self::HEADER, $deviceId);
        if (!$this->cookie || ($request->getCookieParams()[self::COOKIE] ?? null) === $deviceId) {
            return $response;
        }
        $secure = $request->getUri()->getScheme() === 'https' ? '; Secure' : '';

        return $response->withAddedHeader('Set-Cookie', sprintf('%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s', self::COOKIE, $deviceId, self::COOKIE_TTL, $secure));
    }

    /**
     * The user, session and amr of the token pair a successful response carries; null when it has none.
     *
     * @return array{string, string, list<string>}|null
     */
    private function session(ResponseInterface $response): ?array
    {
        if ($response->getStatusCode() !== 200 && $response->getStatusCode() !== 201) {
            return null;
        }
        $body = (string) $response->getBody();
        $response->getBody()->rewind();
        if (!str_contains($body, '"refresh_token"')) {
            return null;
        }
        $data = json_decode($body, true)['data'] ?? null;
        if (!is_array($data) || !is_string($data['access_token'] ?? null) || !is_string($data['refresh_token'] ?? null)) {
            return null;
        }
        try {
            $token = $this->tokens->fromTokenString($data['access_token']);
        } catch (AuthorizationTokenException) {
            return null;
        }
        $userId = $token->getMetadata('sub');
        $sessionId = $token->getMetadata('sid');
        $amr = $token->getMetadata('amr');
        if (!is_string($userId) || !is_string($sessionId) || $sessionId === '') {
            return null;
        }

        return [$userId, $sessionId, is_array($amr) ? array_values(array_filter($amr, 'is_string')) : []];
    }
}
