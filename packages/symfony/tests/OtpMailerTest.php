<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Symfony\Mail\OtpMailer;
use Symfony\Component\Mime\Email;

#[CoversClass(OtpMailer::class)]
final class OtpMailerTest extends TestCase
{
    public function testSendsPlainTextEmailsThroughSymfonyMailer(): void
    {
        $mailer = new RecordingMailer();
        $otpMailer = new OtpMailer($mailer, 'no-reply@example.com');

        $otpMailer->send('ada@example.com', 'otp_code', ['code' => '123456', 'ttl' => 300]);
        $otpMailer->send('ada@example.com', 'mfa_enrolled', ['factor_id' => 'f-1']);

        $sent = $mailer->sent;
        self::assertCount(2, $sent);
        $code = $sent[0];
        self::assertInstanceOf(Email::class, $code);
        self::assertSame('Your verification code', $code->getSubject());
        self::assertSame('ada@example.com', $code->getTo()[0]->getAddress());
        self::assertSame('no-reply@example.com', $code->getFrom()[0]->getAddress());
        self::assertStringContainsString('123456', (string) $code->getTextBody());
        self::assertStringContainsString('300 seconds', (string) $code->getTextBody());
        $generic = $sent[1];
        self::assertInstanceOf(Email::class, $generic);
        self::assertSame('A new authentication factor was added', $generic->getSubject());
        self::assertStringContainsString('factor_id: f-1', (string) $generic->getTextBody());
    }
}
