<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Override;

final class SyncOutbox implements Outbox
{
    #[Override]
    public function push(Message $message, callable $deliver): void
    {
        $deliver($message);
    }
}
