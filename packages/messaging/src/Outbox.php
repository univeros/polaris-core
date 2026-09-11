<?php

declare(strict_types=1);

namespace Polaris\Messaging;

/**
 * Where a send goes once the policy allowed it: synchronously to the channels by default; a host's queue
 * driver implements this to take sends off the request path.
 */
interface Outbox
{
    public function push(Message $message, callable $deliver): void;
}
