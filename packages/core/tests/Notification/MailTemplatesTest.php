<?php

declare(strict_types=1);

namespace Polaris\Tests\Notification;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Notification\MailTemplates;

#[CoversClass(MailTemplates::class)]
final class MailTemplatesTest extends TestCase
{
    public function testKnownTemplatesRenderTheirContextAndUnknownOnesListIt(): void
    {
        self::assertSame('Your verification code', MailTemplates::subject('otp_code'));
        self::assertSame('Account notification', MailTemplates::subject('something_else'));
        self::assertSame("Your verification code is 123456. It expires in 300 seconds.\n", MailTemplates::text('otp_code', ['code' => '123456', 'ttl' => 300]));
        self::assertStringContainsString("tok-1\n", MailTemplates::text('verify_email', ['token' => 'tok-1']));
        self::assertStringContainsString('organization org-1', MailTemplates::text('org_invite', ['token' => 't', 'organization_id' => 'org-1']));
        self::assertSame("Notification: mfa_enrolled\nfactor_id: f-1\nmeta: {\"a\":1}\n", MailTemplates::text('mfa_enrolled', ['factor_id' => 'f-1', 'meta' => ['a' => 1]]));
    }
}
