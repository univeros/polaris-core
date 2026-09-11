<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use Override;
use Polaris\Messaging\Channel;
use Polaris\Messaging\Message;
use Polaris\Messaging\Receipt;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * Development: every message goes to the PSR-3 logger, body included.
 */
final class LogChannel implements Channel
{
    public function __construct(private readonly LoggerInterface $logger, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'log';
    }

    #[Override]
    public function supports(string $kind): bool
    {
        return true;
    }

    #[Override]
    public function send(Message $message): Receipt
    {
        $this->logger->info('[polaris messaging] {kind} {template} to {to}: {subject} {text}', [
            'kind' => $message->kind,
            'template' => $message->template,
            'to' => $message->to,
            'subject' => $message->subject,
            'text' => $message->text,
            'html' => $message->html,
            'vars' => $message->vars,
        ]);

        return new Receipt($this->name(), null, $this->clock->now());
    }
}
