<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use DateTimeImmutable;

/**
 * What a channel answers: which channel took the message, the provider's id when it gives one, when. A
 * queued receipt is an outbox's: the message waits for the worker, no channel has taken it yet.
 */
final readonly class Receipt
{
    public const string QUEUED = 'queued';

    public function __construct(public string $channel, public ?string $providerId, public DateTimeImmutable $sentAt, public bool $queued = false)
    {
    }

    public static function queued(DateTimeImmutable $at): self
    {
        return new self(self::QUEUED, null, $at, true);
    }
}
