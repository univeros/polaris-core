<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Psr15\JsonResponse;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

use function array_filter;
use function array_keys;
use function array_values;
use function dirname;
use function glob;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The middleware against every route the manifests mark (core's and every plugin's): the guard and the
 * plaintext refusal before the handler, in the route's own envelope (docs/cookie-mode/spec.md §5, test
 * 10), the move from body to cookie, and the routes without `session` untouched (test 11).
 */
#[CoversClass(RefreshCookieMiddleware::class)]
final class RefreshCookieMiddlewareTest extends TestCase
{
    private const string SECRET = 'rt_abc-DEF_123';

    /**
     * @return iterable<string, array{EndpointSpec}>
     */
    public static function guardedRoutes(): iterable
    {
        foreach (self::manifest() as $spec) {
            if ($spec->session === 'issue' || $spec->session === 'refresh') {
                yield $spec->route() => [$spec];
            }
        }
    }

    #[DataProvider('guardedRoutes')]
    public function testEveryGuardedRouteRefusesAMissingHeaderInItsOwnEnvelope(EndpointSpec $spec): void
    {
        $handler = new CookieInnerHandler();
        $response = $this->middleware()->process($this->request($spec, headers: []), $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($handler->called, 'the handler never runs');
        $this->assertEnvelope($spec, 'csrf_failed', $response);
    }

    #[DataProvider('guardedRoutes')]
    public function testEveryGuardedRouteRefusesPlaintextInItsOwnEnvelope(EndpointSpec $spec): void
    {
        $handler = new CookieInnerHandler();
        $response = $this->middleware()->process($this->request($spec, scheme: 'http'), $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($handler->called);
        $this->assertEnvelope($spec, 'insecure_transport', $response);
    }

    #[DataProvider('guardedRoutes')]
    public function testEveryGuardedRouteMovesTheRefreshTokenToTheCookie(EndpointSpec $spec): void
    {
        $handler = new CookieInnerHandler(200, ['data' => ['access_token' => 'jwt', 'refresh_token' => self::SECRET, 'user' => ['id' => 'u1', 'meta' => new stdClass()]]]);
        $response = $this->middleware('/api')->process($this->request($spec), $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('{"data":{"access_token":"jwt","user":{"id":"u1","meta":{}}}}', (string) $response->getBody(), 'the key is removed, an empty object stays one');
        self::assertFalse($response->hasHeader('Content-Length'));
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame([
            'polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax',
            '__Secure-polaris_refresh=' . self::SECRET . '; Path=/api/auth/token/refresh; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict',
        ], $response->getHeader('Set-Cookie'), 'added after a cookie the inner middleware set, never replacing it');
    }

    public function testAnMfaTicketOrAnErrorPassesUnchanged(): void
    {
        $login = self::spec('POST /auth/login');
        $ticket = ['data' => ['mfa_required' => true, 'mfa_token' => 't', 'factors' => []]];

        $passed = $this->middleware()->process($this->request($login), new CookieInnerHandler(200, $ticket));
        $failed = $this->middleware()->process($this->request($login), new CookieInnerHandler(401, ['error' => 'invalid_credentials', 'message' => 'x']));

        self::assertSame(json_encode($ticket, JSON_THROW_ON_ERROR), (string) $passed->getBody());
        self::assertSame(['polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax'], $passed->getHeader('Set-Cookie'));
        self::assertSame(401, $failed->getStatusCode());
        self::assertSame(['polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax'], $failed->getHeader('Set-Cookie'));
    }

    public function testTheRefreshReadsTheCookieOnlyWhenNoInputCarriesAToken(): void
    {
        $refresh = self::spec('POST /auth/token/refresh');
        $cookie = [RefreshCookieMiddleware::COOKIE => 'from-cookie'];

        $fromCookie = new CookieInnerHandler(200, []);
        $this->middleware()->process($this->request($refresh, cookies: $cookie), $fromCookie);
        $fromBody = new CookieInnerHandler(200, []);
        $this->middleware()->process($this->request($refresh, ['refresh_token' => 'from-body'], $cookie), $fromBody);
        $fromQuery = new CookieInnerHandler(200, []);
        $this->middleware()->process($this->request($refresh, cookies: $cookie)->withQueryParams(['refresh_token' => 'from-query']), $fromQuery);

        self::assertSame(['refresh_token' => 'from-cookie'], $fromCookie->request?->getParsedBody());
        self::assertSame(['refresh_token' => 'from-body'], $fromBody->request?->getParsedBody());
        self::assertSame([], $fromQuery->request?->getParsedBody());
    }

    public function testAFailedRefreshClearsTheCookieOnlyWhenTheCookieWasTheCredential(): void
    {
        $refresh = self::spec('POST /auth/token/refresh');
        $cookie = [RefreshCookieMiddleware::COOKIE => 'dead'];
        $invalid = ['error' => 'invalid_grant', 'message' => 'x'];

        $byCookie = $this->middleware()->process($this->request($refresh, cookies: $cookie), new CookieInnerHandler(401, $invalid));
        $byBody = $this->middleware()->process($this->request($refresh, ['refresh_token' => 'bad'], $cookie), new CookieInnerHandler(401, $invalid));

        self::assertContains('__Secure-polaris_refresh=; Path=/auth/token/refresh; Max-Age=0; HttpOnly; Secure; SameSite=Strict', $byCookie->getHeader('Set-Cookie'));
        self::assertSame(['polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax'], $byBody->getHeader('Set-Cookie'));
    }

    public function testAnEndRouteClearsTheCookieOnSuccessOnly(): void
    {
        $logout = self::spec('POST /sso/logout');

        $ok = $this->middleware()->process($this->request($logout, headers: [], scheme: 'http'), new CookieInnerHandler(200, ['data' => []]));
        $refused = $this->middleware()->process($this->request($logout), new CookieInnerHandler(401, ['error' => 'unauthorized', 'message' => 'x']));

        self::assertContains('__Secure-polaris_refresh=; Path=/auth/token/refresh; Max-Age=0; HttpOnly; Secure; SameSite=Strict', $ok->getHeader('Set-Cookie'), 'no guard, no scheme check: ending a session is always allowed');
        self::assertSame(['polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax'], $refused->getHeader('Set-Cookie'));
    }

    public function testATrustedOriginPassesTheGuard(): void
    {
        $middleware = $this->middleware(trusted: ['https://app.example.com']);
        $login = self::spec('POST /auth/login');

        $trusted = new CookieInnerHandler(200, []);
        $middleware->process($this->request($login, headers: [RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'https://app.example.com']), $trusted);
        $other = $middleware->process($this->request($login, headers: [RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'https://other.example.com']), new CookieInnerHandler());

        self::assertTrue($trusted->called);
        self::assertSame(403, $other->getStatusCode());
    }

    public function testTheOAuthTokenEndpointIsNotTouched(): void
    {
        $token = self::spec('POST /oauth2/token');
        $body = ['access_token' => 'a', 'token_type' => 'Bearer', 'refresh_token' => 'prt_x'];

        $response = $this->middleware()->process($this->request($token, headers: [], scheme: 'http'), new CookieInnerHandler(200, $body));

        self::assertSame(json_encode($body, JSON_THROW_ON_ERROR), (string) $response->getBody());
        self::assertSame(['polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax'], $response->getHeader('Set-Cookie'));
    }

    private function assertEnvelope(EndpointSpec $spec, string $code, ResponseInterface $response): void
    {
        $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        if ($spec->plugin === null) {
            self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
            self::assertSame(['error', 'message'], array_keys($body));
            self::assertSame($code, $body['error']);

            return;
        }
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        self::assertSame('https://polaris.univeros.io/problems/cookie/' . $code, $body['type']);
        self::assertSame(403, $body['status']);
        self::assertSame($code, $body['error']);
        self::assertSame($body['detail'], $body['message']);
    }

    /**
     * @param list<string> $trusted
     */
    private function middleware(string $prefix = '/', array $trusted = []): RefreshCookieMiddleware
    {
        $auth = AuthConfig::fromArray(['issuer' => 'x', 'flows' => ['token_delivery' => 'cookie', 'cookie' => ['trusted_origins' => $trusted]]]);
        $responses = new ResponseFactory();

        return new RefreshCookieMiddleware($auth, $responses, new JsonResponse($responses), $prefix);
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $cookies
     * @param array<string, string>|null $headers
     */
    private function request(EndpointSpec $spec, array $body = [], array $cookies = [], ?array $headers = null, string $scheme = 'https'): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($spec->method, $scheme . '://auth.example.com' . $spec->path)
            ->withAttribute(Attributes::ROUTE, $spec)
            ->withParsedBody($body)
            ->withCookieParams($cookies);
        foreach ($headers ?? [RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'https://auth.example.com'] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request;
    }

    private static function spec(string $route): EndpointSpec
    {
        foreach (self::manifest() as $spec) {
            if ($spec->route() === $route) {
                return $spec;
            }
        }
        self::fail($route . ' is not in the manifest');
    }

    /**
     * @return list<EndpointSpec>
     */
    private static function manifest(): array
    {
        $packages = dirname(__DIR__, 4);
        $plugins = array_values(array_filter(glob($packages . '/*/api') ?: [], static fn(string $dir): bool => $dir !== $packages . '/core/api'));

        return (new Loader(Loader::defaultDirectory(), ...$plugins))->load()->endpoints();
    }
}
