<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Catalog;
use Polaris\Audit\Redactor;
use Polaris\Audit\Sensitive;

#[CoversClass(Catalog::class)]
#[CoversClass(Redactor::class)]
#[CoversClass(Sensitive::class)]
final class CatalogAndRedactorTest extends TestCase
{
    public function testTheCatalogIsClosedAndExtensible(): void
    {
        $catalog = new Catalog();
        self::assertTrue($catalog->has(Catalog::USER_SIGNED_UP));
        self::assertFalse($catalog->has('billing.invoice_paid'));
        self::assertSame('A user registered', $catalog->all()[Catalog::USER_SIGNED_UP]);

        $catalog->extend(['billing.invoice_paid' => 'An invoice was paid']);
        self::assertTrue($catalog->has('billing.invoice_paid'));
        self::assertSame('billing.invoice_paid', $catalog->names()[count($catalog->names()) - 1]);
        $catalog->assert('billing.invoice_paid');

        try {
            $catalog->extend([Catalog::USER_SIGNED_UP => 'again']);
            self::fail('core names are closed');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('core audit event', $exception->getMessage());
        }
        try {
            $catalog->extend(['Bad Name' => 'x']);
            self::fail('names are namespace.past_tense');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('not a valid audit event name', $exception->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        $catalog->assert('nope.nothing');
    }

    public function testSecretsAreRedactedAtAnyDepthAndByMarker(): void
    {
        $data = [
            'email' => 'ada@example.com',
            'password' => 'hunter2',
            'reset_token' => 'abc',
            'nested' => ['otp_code' => '123456', 'kept' => 1, 'client_secret' => 'x'],
            'answer' => new Sensitive('my dog'),
            'count' => 3,
        ];

        self::assertSame([
            'email' => 'ada@example.com',
            'password' => Redactor::REDACTED,
            'reset_token' => Redactor::REDACTED,
            'nested' => ['otp_code' => Redactor::REDACTED, 'kept' => 1, 'client_secret' => Redactor::REDACTED],
            'answer' => Redactor::REDACTED,
            'count' => 3,
        ], (new Redactor())->redact($data));
    }
}
