<?php

declare(strict_types=1);

namespace Polaris\Notification;

use function is_scalar;
use function json_encode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * Plain-text subjects and bodies for the templates {@see \Polaris\Contract\OtpMailerInterface} is
 * asked to render, for adapters that bridge a framework mailer. The application knows its front end
 * and its wording; this is the working default, not the design.
 */
final class MailTemplates
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

    public static function subject(string $template): string
    {
        return self::SUBJECTS[$template] ?? 'Account notification';
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function text(string $template, array $context): string
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
