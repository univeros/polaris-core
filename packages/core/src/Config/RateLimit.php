<?php

declare(strict_types=1);

namespace Polaris\Config;

use InvalidArgumentException;

use function sprintf;

/**
 * A fixed-window rate-limit policy: at most `$limit` hits per `$windowSeconds`, keyed under `$keyPrefix`.
 */
final readonly class RateLimit
{
    public function __construct(
        public int $limit,
        public int $windowSeconds,
        public string $keyPrefix = 'ratelimit',
    ) {
        if ($limit < 1) {
            throw new InvalidArgumentException(sprintf('Rate-limit `limit` must be >= 1, got %d.', $limit));
        }
        if ($windowSeconds < 1) {
            throw new InvalidArgumentException(sprintf('Rate-limit `windowSeconds` must be >= 1, got %d.', $windowSeconds));
        }
    }
}
