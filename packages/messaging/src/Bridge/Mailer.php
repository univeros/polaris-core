<?php

declare(strict_types=1);

namespace Polaris\Messaging\Bridge;

use Override;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;

/**
 * Core's mail port: the templates core names (`verify_email`, `otp_code`, ...) rendered from the
 * package's keys and sent as email; the verification, reset, invitation and code mails are essential.
 */
final class Mailer implements OtpMailerInterface
{
    public const array TEMPLATES = [
        'verify_email' => 'email.verify',
        'password_reset' => 'email.reset_password',
        'org_invite' => 'email.invite',
        'otp_code' => 'email.otp',
        'account_locked' => 'email.account_locked',
        'password_changed' => 'email.password_changed',
        'mfa_enrolled' => 'email.mfa_enrolled',
        'mfa_factor_removed' => 'email.mfa_factor_removed',
        'recovery_codes_regenerated' => 'email.recovery_codes_regenerated',
        'recovery_code_used' => 'email.recovery_code_used',
    ];
    private const array ESSENTIAL = ['verify_email', 'password_reset', 'org_invite', 'otp_code'];

    public function __construct(private readonly Sender $sender)
    {
    }

    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        $this->sender->send(Message::EMAIL, $toEmail, self::TEMPLATES[$template] ?? 'email.' . $template, $context, essential: in_array($template, self::ESSENTIAL, true));
    }
}
