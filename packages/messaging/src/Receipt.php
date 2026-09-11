<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use DateTimeImmutable;

/**
 * What a channel answers: which channel took the message, the provider's id when it gives one, when.
 */
final readonly class Receipt
{
    public function __construct(public string $channel, public ?string $providerId, public DateTimeImmutable $sentAt)
    {
    }
}
