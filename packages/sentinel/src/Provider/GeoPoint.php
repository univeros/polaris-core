<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use function asin;
use function cos;
use function deg2rad;
use function sin;
use function sqrt;

final readonly class GeoPoint
{
    private const float EARTH_RADIUS_KM = 6371.0;

    public function __construct(public float $latitude, public float $longitude)
    {
    }

    /**
     * Great-circle distance in kilometres (haversine).
     */
    public function distanceTo(self $other): float
    {
        $lat1 = deg2rad($this->latitude);
        $lat2 = deg2rad($other->latitude);
        $dLat = $lat2 - $lat1;
        $dLon = deg2rad($other->longitude - $this->longitude);
        $a = sin($dLat / 2) ** 2 + cos($lat1) * cos($lat2) * sin($dLon / 2) ** 2;

        return 2 * self::EARTH_RADIUS_KM * asin(sqrt($a));
    }
}
