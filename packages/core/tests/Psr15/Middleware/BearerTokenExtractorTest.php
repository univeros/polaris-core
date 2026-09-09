<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Psr15\Middleware\BearerTokenExtractor;
use Psr\Http\Message\ServerRequestInterface;

final class BearerTokenExtractorTest extends TestCase
{
    public function testExtractsTheTokenAfterTheBearerScheme(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('Bearer abc.def.ghi'));
    }

    public function testTheSchemeIsCaseInsensitive(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('bearer abc.def.ghi'));
        self::assertSame('abc.def.ghi', $this->extract('BEARER abc.def.ghi'));
    }

    public function testCollapsesExtraWhitespaceAfterTheScheme(): void
    {
        self::assertSame('abc.def.ghi', $this->extract('Bearer    abc.def.ghi'));
    }

    public function testReturnsNullWhenTheHeaderIsAbsent(): void
    {
        self::assertNull((new BearerTokenExtractor())->extract((new ServerRequestFactory())->createServerRequest('GET', '/')));
    }

    public function testReturnsNullForANonBearerSchemeOrAnEmptyToken(): void
    {
        self::assertNull($this->extract('Basic dXNlcjpwYXNz'));
        self::assertNull($this->extract('Bearer'));
        self::assertNull($this->extract('Bearer   '));
    }

    private function extract(string $authorization): ?string
    {
        return (new BearerTokenExtractor())->extract(
            (new ServerRequestFactory())->createServerRequest('GET', '/')->withHeader('Authorization', $authorization),
        );
    }
}
