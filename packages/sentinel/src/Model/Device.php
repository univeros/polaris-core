<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Model;

use DateTimeImmutable;

/**
 * A device a user signed in from (`polaris_sentinel_device`): the hashed device cookie, the last IP
 * and, when a geo resolver is configured, where; what the device and impossible-travel signals compare.
 */
final class Device
{
    public string $id = '';
    public string $userId = '';
    public string $deviceHash = '';
    public ?string $ip = null;
    /** Decimal degrees as stored (strings, the schema has no float type); null without a geo resolver. */
    public ?string $latitude = null;
    public ?string $longitude = null;
    public DateTimeImmutable $lastSeenAt;
    public DateTimeImmutable $createdAt;
}
