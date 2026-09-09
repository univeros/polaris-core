<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Config\RateLimit;
use Polaris\Contract\RateResult;
use Polaris\Contract\RateStore;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Result;
use Polaris\Psr15\JsonResponse;
use Polaris\Psr15\Middleware\RateLimiter;
use Polaris\Psr15\Router;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Polaris\Tests\Support\FrozenClock;

#[CoversClass(Router::class)]
#[CoversClass(JsonResponse::class)]
#[CoversClass(RateLimiter::class)]
final class RouterTest extends TestCase
{
    public function testMatchesParametersAndReportsAllowedMethods(): void
    {
        $router = new Router((new Loader(Loader::defaultDirectory()))->load(), '/api');

        $match = $router->match('delete', '/api/auth/sessions/0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b');
        self::assertSame('DELETE /auth/sessions/{id}', $match->spec?->route());
        self::assertSame(['id' => '0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b'], $match->params);

        $wrongMethod = $router->match('PUT', '/api/auth/login');
        self::assertNull($wrongMethod->spec);
        self::assertSame(['POST'], $wrongMethod->allowedMethods);

        self::assertNull($router->match('GET', '/api/nope')->spec);
        self::assertSame([], $router->match('GET', '/api/nope')->allowedMethods);
    }

    public function testEmptyResultBodyStaysEmpty(): void
    {
        $json = new JsonResponse(new ResponseFactory());

        $empty = $json->result(new Result(204));
        $full = $json->result(new Result(201, ['data' => ['id' => 1]], ['Location' => '/x']));

        self::assertSame('', (string) $empty->getBody());
        self::assertSame('{"data":{"id":1}}', (string) $full->getBody());
        self::assertSame('/x', $full->getHeaderLine('Location'));
        self::assertSame('application/json', $full->getHeaderLine('Content-Type'));
    }

    public function testRateLimiterAnswers429WithTheHeadersOf10(): void
    {
        $store = new class () implements RateStore {
            public int $hits = 0;

            public function hit(string $key, int $limit, int $windowSeconds): RateResult
            {
                ++$this->hits;

                return new RateResult($this->hits <= $limit, $limit, max(0, $limit - $this->hits), 1_700_000_300);
            }
        };
        $limiter = new RateLimiter($store, new FrozenClock(new \DateTimeImmutable('@1700000000')), new ResponseFactory());
        $handler = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse(200);
            }
        };
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/auth/login');
        $policy = new RateLimit(2, 300, 'login');

        $first = $limiter->limit($policy, 'ip', $request, $handler);
        $limiter->limit($policy, 'ip', $request, $handler);
        $blocked = $limiter->limit($policy, 'ip', $request, $handler);

        self::assertSame(['2', '1', '1700000300'], [$first->getHeaderLine('X-RateLimit-Limit'), $first->getHeaderLine('X-RateLimit-Remaining'), $first->getHeaderLine('X-RateLimit-Reset')]);
        self::assertSame(429, $blocked->getStatusCode());
        self::assertSame('300', $blocked->getHeaderLine('Retry-After'));
        self::assertSame('0', $blocked->getHeaderLine('X-RateLimit-Remaining'));
    }
}
