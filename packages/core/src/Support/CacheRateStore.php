<?php

declare(strict_types=1);

namespace Polaris\Support;

use Override;
use Polaris\Contract\RateResult;
use Polaris\Contract\RateStore;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function hash;
use function intdiv;
use function max;
use function sprintf;

/**
 * The default {@see RateStore}: a fixed-window counter per key in a PSR-16 cache, the algorithm
 * the 1.0 framework limiter used (one bucket per window, the counter expiring with the window).
 */
final class CacheRateStore implements RateStore
{
    public function __construct(private readonly CacheInterface $cache, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function hit(string $key, int $limit, int $windowSeconds): RateResult
    {
        $now = $this->clock->now()->getTimestamp();
        $bucket = intdiv($now, $windowSeconds);
        $resetAt = ($bucket + 1) * $windowSeconds;
        $cacheKey = sprintf('polaris.rate.%s.%d', hash('xxh128', $key), $bucket);
        $count = (int) ($this->cache->get($cacheKey) ?? 0);

        if ($count >= $limit) {
            return new RateResult(false, $limit, 0, $resetAt);
        }
        $this->cache->set($cacheKey, $count + 1, $windowSeconds);

        return new RateResult(true, $limit, max(0, $limit - ($count + 1)), $resetAt);
    }
}
