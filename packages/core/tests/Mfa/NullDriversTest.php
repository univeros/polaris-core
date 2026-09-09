<?php

declare(strict_types=1);

namespace Polaris\Tests\Mfa;

use PHPUnit\Framework\TestCase;
use Polaris\Mfa\NullOtpMailer;
use Polaris\Mfa\NullSmsSender;

final class NullDriversTest extends TestCase
{
    public function testNullDriversAreSilentNoOps(): void
    {
        (new NullSmsSender())->send('+14155550101', 'ignored');
        (new NullOtpMailer())->send('ada@example.com', 'otp_code', ['code' => '123456']);

        // Nothing is delivered, logged, or thrown.
        $this->expectNotToPerformAssertions();
    }
}
