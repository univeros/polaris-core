<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use Override;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\RawMessage;

/**
 * A Symfony mailer that keeps what it was asked to send.
 */
final class RecordingMailer implements MailerInterface
{
    /** @var list<RawMessage> */
    public array $sent = [];

    #[Override]
    public function send(RawMessage $message, ?Envelope $envelope = null): void
    {
        $this->sent[] = $message;
    }
}
