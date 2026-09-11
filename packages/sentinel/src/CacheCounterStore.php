<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Override;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function hash;
use function intdiv;
use function is_int;
use function sprintf;

/**
 * Fixed-window counters in a PSR-16 cache (the same shape as core's rate store): one bucket per window,
 * expiring with it. Redis or any other PSR-16 store works the same.
 */
final class CacheCounterStore implements CounterStore
{
    public function __construct(private readonly CacheInterface $cache, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function increment(string $key, int $windowSeconds): int
    {
        $count = $this->count($key, $windowSeconds) + 1;
        $this->cache->set($this->bucket($key, $windowSeconds), $count, $windowSeconds);

        return $count;
    }

    #[Override]
    public function count(string $key, int $windowSeconds): int
    {
        $count = $this->cache->get($this->bucket($key, $windowSeconds));

        return is_int($count) ? $count : 0;
    }

    #[Override]
    public function reset(string $key, int $windowSeconds): void
    {
        $this->cache->delete($this->bucket($key, $windowSeconds));
    }

    private function bucket(string $key, int $windowSeconds): string
    {
        return sprintf('polaris.sentinel.%s.%d', hash('xxh128', $key), intdiv($this->clock->now()->getTimestamp(), $windowSeconds));
    }
}
