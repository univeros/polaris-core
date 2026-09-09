<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ResponseFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Psr15\Middleware\UnauthorizedResponder;

use function json_decode;

final class UnauthorizedResponderTest extends TestCase
{
    public function testAnswersThe401JsonEnvelopeWithAChallenge(): void
    {
        $response = (new UnauthorizedResponder(new ResponseFactory()))->respond();

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('unauthorized', $body['error']);
        self::assertSame('Authentication is required.', $body['message']);
    }
}
