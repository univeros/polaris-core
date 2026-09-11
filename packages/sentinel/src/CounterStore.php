<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

/**
 * Counts per key in a time window, for the velocity and credential-stuffing signals.
 */
interface CounterStore
{
    /**
     * Adds one and answers the count in the current window.
     */
    public function increment(string $key, int $windowSeconds): int;

    public function count(string $key, int $windowSeconds): int;

    /**
     * Forgets the key's current window (an operator's unblock).
     */
    public function reset(string $key, int $windowSeconds): void;
}
