<?php

declare(strict_types=1);

namespace Polaris\Audit\Query;

use Polaris\Audit\Model\AuditEvent;

use function array_map;

/**
 * One page of events, newest first, and the cursor of the next page (null on the last).
 */
final readonly class Page
{
    /**
     * @param list<AuditEvent> $events
     */
    public function __construct(public array $events, public ?string $nextCursor)
    {
    }

    /**
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function toArray(): array
    {
        return ['data' => array_map(static fn(AuditEvent $event): array => $event->toArray(), $this->events), 'next_cursor' => $this->nextCursor];
    }
}
