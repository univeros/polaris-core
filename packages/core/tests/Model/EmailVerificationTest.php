<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\EmailVerification;

final class EmailVerificationTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $verification = new EmailVerification();

        self::assertSame('', $verification->id);
        self::assertSame('', $verification->userId);
        self::assertSame('', $verification->email);
        self::assertSame('', $verification->tokenHash);
        self::assertNull($verification->consumedAt);
        self::assertNull($verification->ip);
    }
}
