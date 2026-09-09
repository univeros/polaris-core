<?php

declare(strict_types=1);

namespace Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\MfaFactor;

final class MfaFactorTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $factor = new MfaFactor();

        self::assertSame('', $factor->id);
        self::assertSame('', $factor->userId);
        self::assertSame('', $factor->type);
        self::assertNull($factor->label);
        self::assertNull($factor->secretEncrypted);
        self::assertNull($factor->phoneE164);
        self::assertNull($factor->email);
        self::assertFalse($factor->isDefault);
        self::assertNull($factor->confirmedAt);
        self::assertNull($factor->lastUsedAt);
    }

    public function testExposesTheFactorTypes(): void
    {
        self::assertSame('totp', MfaFactor::TYPE_TOTP);
        self::assertSame('sms', MfaFactor::TYPE_SMS);
        self::assertSame('email', MfaFactor::TYPE_EMAIL);
    }
}
