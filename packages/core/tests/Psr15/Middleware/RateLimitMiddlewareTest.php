<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Config\RateLimit;
use Polaris\Config\RateLimitConfig;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\Loader;
use Polaris\Psr15\Middleware\AuthenticatedRateLimitMiddleware;
use Polaris\Psr15\Middleware\AuthRateLimitMiddleware;
use Polaris\Psr15\Middleware\RateLimiter;
use Polaris\Support\CacheRateStore;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Support\CountingRequestHandler;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Token\Token;
use Psr\Http\Message\ServerRequestInterface;

final class RateLimitMiddlewareTest extends TestCase
{
    private CountingRequestHandler $handler;
    private RateLimiter $limiter;
    private RateLimitConfig $limits;

    protected function setUp(): void
    {
        $this->handler = new CountingRequestHandler();
        $clock = FrozenClock::at('2026-06-09 12:00:00');
        $this->limiter = new RateLimiter(new CacheRateStore(new InMemoryCache(), $clock), $clock, new ResponseFactory());
        $defaults = RateLimitConfig::defaults();
        $this->limits = new RateLimitConfig(
            new RateLimit(2, 60, 'auth.login'),
            new RateLimit(5, 60, 'auth.register'),
            $defaults->passwordForgot,
            $defaults->tokenRefresh,
            $defaults->mfaEnroll,
            $defaults->mfaConfirm,
            $defaults->mfaSend,
            $defaults->tokenConsume,
            new RateLimit(2, 60, 'auth.authenticated'),
        );
    }

    public function testAuthBudgetsFollowTheSpecGroupAndAreCountedIndependently(): void
    {
        $middleware = new AuthRateLimitMiddleware($this->limits, $this->limiter);

        $first = $middleware->process($this->routed('POST', '/auth/login'), $this->handler);
        self::assertSame(['2', '1'], [$first->getHeaderLine('X-RateLimit-Limit'), $first->getHeaderLine('X-RateLimit-Remaining')]);
        $middleware->process($this->routed('POST', '/auth/login'), $this->handler);
        $blocked = $middleware->process($this->routed('POST', '/auth/login'), $this->handler);
        self::assertSame(429, $blocked->getStatusCode());
        self::assertNotSame('', $blocked->getHeaderLine('Retry-After'));
        self::assertSame(2, $this->handler->calls, 'the blocked request never reaches the handler');
        self::assertSame(200, $middleware->process($this->routed('POST', '/auth/register'), $this->handler)->getStatusCode());
    }

    public function testARouteWithoutARateLimitGroupPassesThroughUntouched(): void
    {
        $response = (new AuthRateLimitMiddleware($this->limits, $this->limiter))->process($this->routed('GET', '/auth/me'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('X-RateLimit-Limit'));
    }

    public function testAuthenticatedUsersAreBudgetedPerSubjectAcrossEndpoints(): void
    {
        $middleware = new AuthenticatedRateLimitMiddleware($this->limits, $this->limiter);

        self::assertSame(200, $middleware->process($this->authed('user-1', '/auth/me'), $this->handler)->getStatusCode());
        self::assertSame(200, $middleware->process($this->authed('user-1', '/orgs'), $this->handler)->getStatusCode());
        self::assertSame(429, $middleware->process($this->authed('user-1', '/auth/sessions'), $this->handler)->getStatusCode());
        self::assertSame(200, $middleware->process($this->authed('user-2', '/auth/me'), $this->handler)->getStatusCode(), 'per user, not per IP');
        self::assertSame(3, $this->handler->calls);
    }

    public function testARequestWithoutATokenPassesThroughUntouched(): void
    {
        $response = (new AuthenticatedRateLimitMiddleware($this->limits, $this->limiter))->process($this->routed('POST', '/auth/login'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('X-RateLimit-Limit'), 'unauthenticated requests get no limiter headers');
    }

    private function routed(string $method, string $path): ServerRequestInterface
    {
        $spec = (new Loader(Loader::defaultDirectory()))->load()->find($method, $path);
        self::assertNotNull($spec);

        return (new ServerRequestFactory())->createServerRequest($method, $path, ['REMOTE_ADDR' => '203.0.113.7'])->withAttribute(Attributes::ROUTE, $spec);
    }

    private function authed(string $subject, string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('GET', $path)->withAttribute(Attributes::TOKEN, new Token('jwt', ['sub' => $subject]));
    }
}
