<?php

declare(strict_types=1);

namespace Polaris\Messaging;

/**
 * Where a send goes once the policy allowed it. The outbox receives data, both parts serializable: the
 * message and the alternative recipients its fallback may use. `SyncOutbox` (the default) delivers at once
 * through `Sender::dispatch()` and answers the channel's receipt, or null when no channel delivered it. A
 * host's queue puts both on the queue and answers `Receipt::queued()`; its worker calls
 * `Sender::dispatch()` with them, which neither asks the policy again nor comes back to the outbox.
 */
interface Outbox
{
    /**
     * @param array<string, string> $alternatives kind => recipient
     */
    public function push(Message $message, array $alternatives): ?Receipt;
}
