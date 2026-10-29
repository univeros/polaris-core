<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The inner stack: answers a fixed JSON body and, like `polaris/multi-session`'s `DeviceMiddleware`,
 * has already added a cookie of its own.
 */
final class CookieInnerHandler implements RequestHandlerInterface
{
    public bool $called = false;
    public ?ServerRequestInterface $request = null;

    /**
     * @param array<string, mixed> $body
     */
    public function __construct(private readonly int $status = 200, private readonly array $body = [])
    {
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->called = true;
        $this->request = $request;
        $response = (new ResponseFactory())->createResponse($this->status)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Content-Length', '999')
            ->withAddedHeader('Set-Cookie', 'polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax');
        $response->getBody()->write(json_encode($this->body, JSON_THROW_ON_ERROR));

        return $response;
    }
}
