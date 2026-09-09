<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Http\Attributes;
use Polaris\Psr15\Middleware\ClientContextMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function str_repeat;
use function strlen;

final class ClientContextMiddlewareTest extends TestCase
{
    public function testAttachesTheUserAgentAndTheRemoteAddress(): void
    {
        $seen = $this->process($this->request()->withHeader('User-Agent', 'Browser/1.0'));

        self::assertSame('Browser/1.0', $seen->getAttribute(Attributes::USER_AGENT));
        self::assertSame('203.0.113.7', $seen->getAttribute(Attributes::IP_ADDRESS));
    }

    public function testStripsControlCharactersAndTruncatesToTheColumnSize(): void
    {
        $hostile = "Evil/1.0\tInjected" . str_repeat('a', 300);
        $seen = $this->process($this->request()->withHeader('User-Agent', $hostile));
        $attribute = (string) $seen->getAttribute(Attributes::USER_AGENT);

        self::assertStringNotContainsString("\t", $attribute);
        self::assertSame(255, strlen($attribute), 'bounded to the user_agent column size');
        self::assertStringStartsWith('Evil/1.0Injected', $attribute);
    }

    public function testAnAbsentHeaderSetsNoAttributeAndAPresetIpIsKept(): void
    {
        $seen = $this->process($this->request()->withAttribute(Attributes::IP_ADDRESS, '198.51.100.9'));

        self::assertNull($seen->getAttribute(Attributes::USER_AGENT));
        self::assertSame('198.51.100.9', $seen->getAttribute(Attributes::IP_ADDRESS), 'an adapter-set address wins over REMOTE_ADDR');
    }

    private function process(ServerRequestInterface $request): ServerRequestInterface
    {
        $handler = new class () implements RequestHandlerInterface {
            public ?ServerRequestInterface $request = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->request = $request;

                return new Response();
            }
        };
        (new ClientContextMiddleware())->process($request, $handler);
        self::assertNotNull($handler->request);

        return $handler->request;
    }

    private function request(): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('POST', '/auth/login', ['REMOTE_ADDR' => '203.0.113.7']);
    }
}
