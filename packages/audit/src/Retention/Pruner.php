<?php

declare(strict_types=1);

namespace Polaris\Audit\Retention;

use DateTimeImmutable;
use Polaris\Audit\Catalog;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Store;
use Psr\Clock\ClockInterface;

use function in_array;

use const DATE_ATOM;

/**
 * Deletes what the policy no longer keeps: the names with their own duration first, then everything
 * else at the default. With the hash chain on, the run ends with an `audit.pruned` checkpoint carrying
 * the hash of the newest pruned event, which is what lets {@see Verifier} accept the gap.
 */
final class Pruner
{
    public function __construct(
        private readonly Store $store,
        private readonly Catalog $catalog,
        private readonly RetentionPolicy $policy,
        private readonly ClockInterface $clock,
        private readonly bool $hashChain = false,
    ) {
    }

    /**
     * @return int the number of events deleted
     */
    public function prune(): int
    {
        $now = $this->clock->now();
        $deleted = 0;
        $lastHash = null;
        $before = null;
        foreach ($this->policy->overridden() as $name) {
            $until = $this->policy->keepUntil($name, $now);
            $newest = $this->store->newestBefore($until, $name);
            if ($newest !== null && ($lastHash === null || $newest->id > $lastHash[0])) {
                $lastHash = [$newest->id, $newest->hash];
            }
            $deleted += $this->store->deleteBefore($until, $name);
        }
        $default = $this->policy->keepUntil(Catalog::AUDIT_PRUNED, $now);
        $newest = $this->store->newestBefore($default);
        if ($newest !== null && ($lastHash === null || $newest->id > $lastHash[0])) {
            $lastHash = [$newest->id, $newest->hash];
        }
        $deleted += $this->deleteAtDefault($default);
        if ($this->hashChain && $deleted > 0) {
            $this->store->write(AuditEvent::of(Catalog::AUDIT_PRUNED, $now, data: ['count' => $deleted, 'before' => $default->format(DATE_ATOM), 'last_hash' => $lastHash[1] ?? null]));
        }

        return $deleted;
    }

    /**
     * Everything without a duration of its own; the overridden names were handled at theirs.
     */
    private function deleteAtDefault(DateTimeImmutable $until): int
    {
        $deleted = 0;
        foreach ($this->namesAtDefault() as $name) {
            $deleted += $this->store->deleteBefore($until, $name);
        }

        return $deleted;
    }

    /**
     * @return list<string>
     */
    private function namesAtDefault(): array
    {
        $names = [];
        foreach ($this->catalog->names() as $name) {
            if (!in_array($name, $this->policy->overridden(), true)) {
                $names[] = $name;
            }
        }

        return $names;
    }
}
