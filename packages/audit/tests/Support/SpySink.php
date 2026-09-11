<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests\Support;

use Override;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Sink\AuditSink;

final class SpySink implements AuditSink
{
    /** @var list<AuditEvent> */
    public array $events = [];

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        foreach ($events as $event) {
            $this->events[] = $event;
        }
    }
}
