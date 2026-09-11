<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;

/**
 * No geo database: the impossible-travel signal stays silent.
 */
final class NullResolver implements GeoResolver
{
    #[Override]
    public function resolve(string $ip): ?GeoPoint
    {
        return null;
    }
}
