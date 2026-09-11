<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use MaxMind\Db\Reader;
use Override;
use Throwable;

use function is_array;
use function is_numeric;

/**
 * A MaxMind database (GeoLite2-City or GeoIP2-City, the host's own copy) through `maxmind-db/reader`.
 */
final class MaxMindGeoResolver implements GeoResolver
{
    private ?Reader $reader = null;

    public function __construct(private readonly string $databasePath)
    {
    }

    #[Override]
    public function resolve(string $ip): ?GeoPoint
    {
        try {
            $record = ($this->reader ??= new Reader($this->databasePath))->get($ip);
        } catch (Throwable) {
            return null;
        }
        $location = is_array($record) && is_array($record['location'] ?? null) ? $record['location'] : [];
        $latitude = $location['latitude'] ?? null;
        $longitude = $location['longitude'] ?? null;

        return is_numeric($latitude) && is_numeric($longitude) ? new GeoPoint((float) $latitude, (float) $longitude) : null;
    }
}
