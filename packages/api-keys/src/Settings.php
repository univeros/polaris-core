<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use LogicException;

use function in_array;

/**
 * The plugin's configuration: the environment a key is minted for by default (`pk_live_` or
 * `pk_test_`), how long a rotated key's predecessor stays valid, how many live keys an owner may hold,
 * and the ceiling of a key's own rate limit.
 */
final readonly class Settings
{
    public const string LIVE = 'live';
    public const string TEST = 'test';

    public function __construct(
        public string $environment = self::LIVE,
        public int $rotationGrace = 86400,
        public int $maxPerOwner = 50,
        public int $maxRateLimitWindow = 86400,
    ) {
        if (!in_array($environment, [self::LIVE, self::TEST], true)) {
            throw new LogicException('environment must be live or test.');
        }
        if ($rotationGrace < 0 || $maxPerOwner < 1 || $maxRateLimitWindow < 1) {
            throw new LogicException('rotationGrace must be zero or more; maxPerOwner and maxRateLimitWindow at least one.');
        }
    }

    public static function prefix(string $environment): string
    {
        return 'pk_' . $environment . '_';
    }
}
