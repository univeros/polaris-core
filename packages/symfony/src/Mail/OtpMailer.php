<?php

declare(strict_types=1);

namespace Polaris\Symfony\Mail;

use Override;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Notification\MailTemplates;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * `polaris.mailer: mail`: Polaris emails go through Symfony Mailer as plain text
 * ({@see MailTemplates}); `polaris.mail_from` sets the sender.
 */
final readonly class OtpMailer implements OtpMailerInterface
{
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
            ->subject(MailTemplates::subject($template))
            ->text(MailTemplates::text($template, $context));
        if ($this->from !== null) {
            $email->from($this->from);
        }
        $this->mailer->send($email);
    }
}
