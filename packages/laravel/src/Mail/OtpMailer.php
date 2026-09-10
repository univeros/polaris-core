<?php

declare(strict_types=1);

namespace Polaris\Laravel\Mail;

use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Contracts\View\Factory;
use Illuminate\Mail\Message;
use Override;
use Polaris\Contract\OtpMailerInterface;

/**
 * `mailer: mail`: Polaris emails go through Laravel's mailer as plain text rendered from the
 * `polaris::mail.<template>` view (publishable with `--tag=polaris-views`), or the generic
 * `polaris::mail.notification` when no view exists for the template.
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

    public function __construct(private Mailer $mailer, private Factory $views)
    {
    }

    /**
     * @param array<string, mixed> $context
     */
    #[Override]
    public function send(string $toEmail, string $template, array $context): void
    {
        $view = $this->views->exists('polaris::mail.' . $template) ? 'polaris::mail.' . $template : 'polaris::mail.notification';
        $subject = self::SUBJECTS[$template] ?? 'Account notification';
        $this->mailer->send(['text' => $view], ['template' => $template, 'context' => $context], static function (Message $message) use ($toEmail, $subject): void {
            $message->to($toEmail)->subject($subject);
        });
    }
}
