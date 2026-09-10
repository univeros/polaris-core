<?php

declare(strict_types=1);

namespace Polaris\Symfony\Mail;

use Override;
use Polaris\Contract\OtpMailerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

use function is_scalar;
use function json_encode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * `polaris.mailer: mail`: Polaris emails go through Symfony Mailer as plain text, one body per common
 * template and a generic one listing the context otherwise. The application knows its front end and
 * its wording; this is the working default, not the design.
 */
final readonly class OtpMailer implements OtpMailerInterface
{
    private const array SUBJECTS = [
        'verify_email' => 'Verify your email address',
        'password_reset' => 'Reset your password',
        'org_invite' => 'You have been invited to an organization',
        'otp_code' => 'Your verification code',
        'account_locked' => 'Your account has been locked',
        'password_changed' => 'Your password was changed',
        'mfa_enrolled' => 'A new authentication factor was added',
        'mfa_factor_removed' => 'An authentication factor was removed',
        'recovery_code_used' => 'A recovery code was used',
        'recovery_codes_regenerated' => 'Your recovery codes were regenerated',
    ];

    public function __construct(private MailerInterface $mailer, private ?string $from = null)
    {
    }

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        $email = (new Email())
            ->to($toEmail)
            ->subject(self::SUBJECTS[$template] ?? 'Account notification')
            ->text(self::render($template, $context));
        if ($this->from !== null) {
            $email->from($this->from);
        }
        $this->mailer->send($email);
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function render(string $template, array $context): string
    {
        $value = static fn (string $key): string => is_scalar($context[$key] ?? null) ? (string) $context[$key] : '';

        return match ($template) {
            'verify_email' => sprintf("Use this token to verify your email address:\n\n%s\n", $value('token')),
            'password_reset' => sprintf("Use this token to reset your password. If you did not ask for a reset, ignore this message.\n\n%s\n", $value('token')),
            'org_invite' => sprintf("You have been invited to join organization %s. Use this token to accept the invitation:\n\n%s\n", $value('organization_id'), $value('token')),
            'otp_code' => sprintf("Your verification code is %s. It expires in %d seconds.\n", $value('code'), (int) $value('ttl')),
            default => self::generic($template, $context),
        };
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function generic(string $template, array $context): string
    {
        $lines = sprintf("Notification: %s\n", $template);
        foreach ($context as $key => $value) {
            $lines .= sprintf("%s: %s\n", $key, is_scalar($value) ? (string) $value : json_encode($value, JSON_THROW_ON_ERROR));
        }

        return $lines;
    }
}
