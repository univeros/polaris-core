<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\TokenGeneratorInterface;
use Polaris\Contract\TokenParserInterface;
use Polaris\Exception\InvalidTokenException;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\MfaTicket;
use Polaris\Psr15\Middleware\MfaTokenMiddleware;
use Polaris\Psr15\Middleware\UnauthorizedResponder;
use Polaris\Tests\Support\CountingRequestHandler;
use Polaris\Token\MfaLoginTokenService;
use Polaris\Token\Token;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class MfaTokenMiddlewareTest extends TestCase
{
    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new CountingRequestHandler();
    }

    public function testARequestOutsideTheGatePassesThroughUntouched(): void
    {
        $response = $this->middleware($this->tickets())->process($this->routed('GET', '/auth/me'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testAValidTicketAttachesTheUserIdAndDelegates(): void
    {
        $handler = new class () implements RequestHandlerInterface {
            public mixed $ticket = 'unset';

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->ticket = $request->getAttribute(Attributes::MFA_TICKET);

                return (new ResponseFactory())->createResponse(200);
            }
        };

        $response = $this->middleware($this->tickets())->process($this->routed('POST', '/auth/mfa/verify')->withHeader('Authorization', 'Bearer good-ticket'), $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertInstanceOf(MfaTicket::class, $handler->ticket);
        self::assertSame('user-1', $handler->ticket->userId);
    }

    public function testAMissingOrInvalidTicketIsRejected(): void
    {
        self::assertSame(401, $this->middleware($this->tickets())->process($this->routed('POST', '/auth/mfa/verify'), $this->handler)->getStatusCode());
        self::assertSame(401, $this->middleware($this->tickets(throw: true))->process($this->routed('POST', '/auth/mfa/verify')->withHeader('Authorization', 'Bearer bad'), $this->handler)->getStatusCode());
        self::assertSame(0, $this->handler->calls, 'the gate endpoint is never reached');
    }

    private function middleware(MfaLoginTokenService $tickets): MfaTokenMiddleware
    {
        return new MfaTokenMiddleware($tickets, new UnauthorizedResponder(new ResponseFactory()));
    }

    private function tickets(bool $throw = false): MfaLoginTokenService
    {
        $parser = $this->createStub(TokenParserInterface::class);
        if ($throw) {
            $parser->method('parse')->willThrowException(new InvalidTokenException('bad'));
        } else {
            $parser->method('parse')->willReturn(new Token('ticket', ['purpose' => MfaLoginTokenService::PURPOSE, 'sub' => 'user-1']));
        }

        return new MfaLoginTokenService($this->createStub(TokenGeneratorInterface::class), $parser);
    }

    private function routed(string $method, string $path): ServerRequestInterface
    {
        $spec = (new Loader(Loader::defaultDirectory()))->load()->find($method, $path);
        self::assertNotNull($spec);

        return (new ServerRequestFactory())->createServerRequest($method, $path)->withAttribute(Attributes::ROUTE, $spec);
    }
}
