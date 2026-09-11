<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

/**
 * Where an address is; null when unknown (private ranges, no database).
 */
interface GeoResolver
{
    public function resolve(string $ip): ?GeoPoint;
}
