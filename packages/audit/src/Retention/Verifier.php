<?php

declare(strict_types=1);

namespace Polaris\Audit\Retention;

use Polaris\Audit\Catalog;
use Polaris\Audit\Store;

use function in_array;
use function sprintf;

/**
 * Walks the chain in order: every row's hash must be its recomputed hash, and its `prev_hash` the
 * previous row's hash, or the `last_hash` of a pruning checkpoint when the rows before it were
 * pruned. Reports each break.
 */
final class Verifier
{
    public function __construct(private readonly Store $store)
    {
    }

    /**
     * @return array{rows: int, breaks: list<string>}
     */
    public function verify(): array
    {
        $checkpoints = $this->store->checkpointHashes();
        $previous = null;
        $rows = 0;
        $breaks = [];
        foreach ($this->store->walk() as $event) {
            ++$rows;
            if ($event->hash === null) {
                $breaks[] = sprintf('%s (%s) has no hash', $event->id, $event->name);
                $previous = null;
                continue;
            }
            if ($event->hash !== Store::hashOf($event)) {
                $breaks[] = sprintf('%s (%s) was altered', $event->id, $event->name);
            }
            if ($event->prevHash !== $previous && !($previous === null && $event->name === Catalog::AUDIT_PRUNED) && !in_array($event->prevHash, $checkpoints, true)) {
                $breaks[] = sprintf('%s (%s) does not follow the previous row', $event->id, $event->name);
            }
            $previous = $event->hash;
        }

        return ['rows' => $rows, 'breaks' => $breaks];
    }
}
