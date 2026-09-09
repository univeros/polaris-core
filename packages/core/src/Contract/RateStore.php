<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * Fixed-window rate limiting: counts hits per key inside windows of `$windowSeconds`.
 */
interface RateStore
{
    public function hit(string $key, int $limit, int $windowSeconds): RateResult;
}
