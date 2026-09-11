<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Sentinel\Model\Device;
use Polaris\Sentinel\Provider\GeoPoint;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function hash;
use function is_numeric;
use function is_string;

/**
 * The devices a user signed in from, by hashed device cookie, with the last address and location.
 */
final class Devices
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public static function hash(string $deviceId): string
    {
        return hash('sha256', $deviceId);
    }

    public function find(string $userId, string $deviceId): ?Device
    {
        $row = $this->database->findOne(Schema::DEVICES, ['user_id' => $userId, 'device_hash' => self::hash($deviceId)]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * The device the user last signed in from.
     */
    public function latest(string $userId): ?Device
    {
        $rows = $this->database->findMany(Schema::DEVICES, ['user_id' => $userId], ['last_seen_at' => 'desc'], 1);

        return $rows === [] ? null : self::hydrate($rows[0]);
    }

    public function record(string $userId, string $deviceId, ?string $ip, ?GeoPoint $location): void
    {
        $now = $this->clock->now();
        $data = [
            'ip' => $ip,
            'latitude' => $location === null ? null : (string) $location->latitude,
            'longitude' => $location === null ? null : (string) $location->longitude,
            'last_seen_at' => $now,
        ];
        $hash = self::hash($deviceId);
        if ($this->database->update(Schema::DEVICES, ['user_id' => $userId, 'device_hash' => $hash], $data) === 0) {
            $this->database->insert(Schema::DEVICES, ['id' => Uuid::v7()->toRfc4122(), 'user_id' => $userId, 'device_hash' => $hash, ...$data, 'created_at' => $now]);
        }
    }

    public function countFor(string $userId): int
    {
        return $this->database->count(Schema::DEVICES, ['user_id' => $userId]);
    }

    public static function location(Device $device): ?GeoPoint
    {
        return is_numeric($device->latitude) && is_numeric($device->longitude) ? new GeoPoint((float) $device->latitude, (float) $device->longitude) : null;
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Device
    {
        $device = new Device();
        $device->id = (string) $row['id'];
        $device->userId = (string) $row['user_id'];
        $device->deviceHash = (string) $row['device_hash'];
        $device->ip = is_string($row['ip'] ?? null) && $row['ip'] !== '' ? $row['ip'] : null;
        $device->latitude = is_string($row['latitude'] ?? null) && $row['latitude'] !== '' ? $row['latitude'] : null;
        $device->longitude = is_string($row['longitude'] ?? null) && $row['longitude'] !== '' ? $row['longitude'] : null;
        $device->lastSeenAt = self::datetime($row['last_seen_at']);
        $device->createdAt = self::datetime($row['created_at']);

        return $device;
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
