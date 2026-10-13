<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Closure;
use Override;

/**
 * Delivers on the request: the default outbox.
 */
final class SyncOutbox implements Outbox
{
    /**
     * @param Closure(): Sender $sender resolved at the first send, because the sender holds this outbox
     */
    public function __construct(private readonly Closure $sender)
    {
    }

    #[Override]
    public function push(Message $message, array $alternatives): ?Receipt
    {
        return ($this->sender)()->dispatch($message, $alternatives);
    }
}
