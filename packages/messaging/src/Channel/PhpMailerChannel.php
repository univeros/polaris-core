<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use Override;
use PHPMailer\PHPMailer\PHPMailer;
use Polaris\Messaging\Channel;
use Polaris\Messaging\DeliveryException;
use Polaris\Messaging\Message;
use Polaris\Messaging\Receipt;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Email through a configured PHPMailer instance (SMTP, sendmail, mail()); the instance is cloned per send.
 */
final class PhpMailerChannel implements Channel
{
    public function __construct(private readonly PHPMailer $mailer, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'phpmailer';
    }

    #[Override]
    public function supports(string $kind): bool
    {
        return $kind === Message::EMAIL;
    }

    #[Override]
    public function send(Message $message): Receipt
    {
        $mail = clone $this->mailer;
        try {
            $mail->clearAllRecipients();
            $mail->addAddress($message->to);
            $mail->Subject = (string) $message->subject;
            if ($message->html !== null) {
                $mail->isHTML(true);
                $mail->Body = $message->html;
                $mail->AltBody = $message->text;
            } else {
                $mail->isHTML(false);
                $mail->Body = $message->text;
            }
            if (!$mail->send()) {
                throw new DeliveryException($mail->ErrorInfo);
            }
        } catch (DeliveryException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new DeliveryException($exception->getMessage(), 0, $exception);
        }

        return new Receipt($this->name(), $mail->getLastMessageID() !== '' ? $mail->getLastMessageID() : null, $this->clock->now());
    }
}
