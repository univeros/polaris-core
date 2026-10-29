<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Psr\Http\Message\ResponseInterface;

use function array_shift;
use function explode;
use function rawurldecode;
use function str_contains;
use function strtolower;
use function trim;

/**
 * Requests and assertions for cookie token delivery (docs/cookie-mode/spec.md §5), for a
 * {@see FunctionalTestCase} that turns it on through `authConfig()`. Requests carry a full URI, so the
 * Laravel and Symfony harnesses get `HTTPS=on` from the scheme, and cookies as cookie params, which is
 * what HttpFoundation and the middleware read.
 */
trait CookieRequests
{
    /** @var array<string, string> */
    private static array $sameOrigin = [RefreshCookieMiddleware::CSRF_HEADER => '1'];

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $cookies
     * @param array<string, string>|null $headers null for the CSRF header a cookie-mode client sends
     */
    protected function send(string $path, array $body = [], array $cookies = [], ?array $headers = null, string $scheme = 'https', ?string $accessToken = null, string $method = 'POST'): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $scheme . '://localhost' . $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body)
            ->withCookieParams($cookies);
        foreach ($headers ?? self::$sameOrigin as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        if ($accessToken !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $accessToken);
        }

        return $this->handle($request);
    }

    /**
     * The `Set-Cookie` headers, parsed: name => value and lower-cased attributes. Hosts re-serialise
     * them (Symfony lower-cases attributes, adds `expires`, writes a cleared value as `deleted`), so tests
     * compare these, never the raw string.
     *
     * @return array<string, array{value: string, attributes: array<string, string>}>
     */
    protected static function cookies(ResponseInterface $response): array
    {
        $cookies = [];
        foreach ($response->getHeader('Set-Cookie') as $line) {
            $parts = explode(';', $line);
            [$name, $value] = explode('=', (string) array_shift($parts), 2) + [1 => ''];
            $attributes = [];
            foreach ($parts as $part) {
                [$key, $attribute] = explode('=', trim($part), 2) + [1 => ''];
                $attributes[strtolower($key)] = $attribute;
            }
            $cookies[trim($name)] = ['value' => rawurldecode($value), 'attributes' => $attributes];
        }

        return $cookies;
    }

    /**
     * Asserts the refresh cookie of §2.4 was set and answers its value.
     */
    protected function assertRefreshCookieSet(ResponseInterface $response, string $path = '/auth/token/refresh'): string
    {
        $cookie = self::cookies($response)[RefreshCookieMiddleware::COOKIE] ?? null;
        self::assertNotNull($cookie, 'the refresh cookie is set');
        self::assertNotSame('', $cookie['value']);
        self::assertSame($path, $cookie['attributes']['path'] ?? null);
        // Laravel re-serialises Max-Age from the expiry it computed, a second or so lower.
        self::assertEqualsWithDelta(2592000, (int) ($cookie['attributes']['max-age'] ?? 0), 5);
        self::assertArrayHasKey('httponly', $cookie['attributes']);
        self::assertArrayHasKey('secure', $cookie['attributes']);
        self::assertSame('strict', strtolower($cookie['attributes']['samesite'] ?? ''));
        self::assertArrayNotHasKey('domain', $cookie['attributes']);

        return $cookie['value'];
    }

    protected function assertRefreshCookieCleared(ResponseInterface $response): void
    {
        $cookie = self::cookies($response)[RefreshCookieMiddleware::COOKIE] ?? null;
        self::assertNotNull($cookie, 'the refresh cookie is cleared');
        self::assertSame('0', $cookie['attributes']['max-age'] ?? null);
        self::assertContains($cookie['value'], ['', 'deleted']);
    }

    protected function assertNoRefreshCookie(ResponseInterface $response): void
    {
        self::assertArrayNotHasKey(RefreshCookieMiddleware::COOKIE, self::cookies($response));
    }

    protected function assertNoRefreshTokenInBody(ResponseInterface $response): void
    {
        self::assertFalse(str_contains((string) $response->getBody(), '"refresh_token"'), 'no refresh_token in the body');
    }
}
