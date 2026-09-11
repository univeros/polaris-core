<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Override;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Store;

/**
 * The default sink: the store, hash chain included when enabled.
 */
final readonly class DatabaseSink implements AuditSink
{
    public function __construct(private Store $store)
    {
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        foreach ($events as $event) {
            $this->store->write($event);
        }
    }
}
