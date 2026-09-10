<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Yii\Mail\OtpMailer;
use Yiisoft\Mailer\StubMailer;

#[CoversClass(OtpMailer::class)]
final class OtpMailerTest extends TestCase
{
    public function testSendsPlainTextMessagesThroughTheYiiMailer(): void
    {
        $mailer = new StubMailer();
        $otpMailer = new OtpMailer($mailer, 'no-reply@example.com');

        $otpMailer->send('ada@example.com', 'otp_code', ['code' => '123456', 'ttl' => 300]);
        $otpMailer->send('ada@example.com', 'mfa_enrolled', ['factor_id' => 'f-1']);

        $messages = $mailer->getMessages();
        self::assertCount(2, $messages);
        self::assertSame('Your verification code', $messages[0]->getSubject());
        self::assertSame('ada@example.com', $messages[0]->getTo());
        self::assertSame('no-reply@example.com', $messages[0]->getFrom());
        self::assertStringContainsString('123456', (string) $messages[0]->getTextBody());
        self::assertSame('A new authentication factor was added', $messages[1]->getSubject());
        self::assertStringContainsString('factor_id: f-1', (string) $messages[1]->getTextBody());
    }
}
