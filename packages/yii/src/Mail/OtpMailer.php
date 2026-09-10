<?php

declare(strict_types=1);

namespace Polaris\Yii\Mail;

use Override;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Notification\MailTemplates;
use Yiisoft\Mailer\MailerInterface;
use Yiisoft\Mailer\Message;

/**
 * `polaris.mailer: mail`: Polaris emails go through the Yii mailer as plain text
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
        $message = (new Message())
            ->withTo($toEmail)
            ->withSubject(MailTemplates::subject($template))
            ->withTextBody(MailTemplates::text($template, $context));
        if ($this->from !== null) {
            $message = $message->withFrom($this->from);
        }
        $this->mailer->send($message);
    }
}
