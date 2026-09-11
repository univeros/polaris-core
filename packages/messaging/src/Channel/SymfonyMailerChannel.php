<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use Override;
use Polaris\Messaging\Channel;
use Polaris\Messaging\DeliveryException;
use Polaris\Messaging\Message;
use Polaris\Messaging\Receipt;
use Psr\Clock\ClockInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Throwable;

/**
 * Email through symfony/mailer (any of its transports).
 */
final class SymfonyMailerChannel implements Channel
{
    public function __construct(private readonly MailerInterface $mailer, private readonly string $from, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'symfony_mailer';
    }

    #[Override]
    public function supports(string $kind): bool
    {
        return $kind === Message::EMAIL;
    }

    #[Override]
    public function send(Message $message): Receipt
    {
        $email = (new Email())->from($this->from)->to($message->to)->subject((string) $message->subject)->text($message->text);
        if ($message->html !== null) {
            $email->html($message->html);
        }
        try {
            $this->mailer->send($email);
        } catch (Throwable $exception) {
            throw new DeliveryException($exception->getMessage(), 0, $exception);
        }

        return new Receipt($this->name(), null, $this->clock->now());
    }
}
