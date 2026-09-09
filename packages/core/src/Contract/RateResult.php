<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * The outcome of one {@see RateStore::hit()}: whether the hit fits the window and the counters
 * the rate-limit headers report.
 */
final readonly class RateResult
{
    public function __construct(
        public bool $allowed,
        public int $limit,
        public int $remaining,
        public int $resetAt,
    ) {
    }

    public function retryAfter(int $now): int
    {
        return max(0, $this->resetAt - $now);
    }
}
