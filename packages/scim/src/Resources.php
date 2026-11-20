<?php

declare(strict_types=1);

namespace Polaris\Scim;

use DateTimeImmutable;
use DateTimeInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Scim\Model\Connection;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * The directory's external ids (`polaris_scim_resource`) and the memberships a connection created
 * (`polaris_scim_membership_provenance`).
 */
final class Resources
{
    private const string SECOND = 'Y-m-d H:i:s';

    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public function externalId(Connection $connection, string $kind, string $localId): ?string
    {
        $row = $this->database->findOne(Schema::RESOURCES, ['connection_id' => $connection->id, 'kind' => $kind, 'local_id' => $localId]);
        $value = $row['external_id'] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The local id the directory's external id names; null when unknown.
     */
    public function localId(Connection $connection, string $kind, string $externalId): ?string
    {
        $row = $this->database->findOne(Schema::RESOURCES, ['connection_id' => $connection->id, 'kind' => $kind, 'external_id' => $externalId]);
        $value = $row['local_id'] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function setExternalId(Connection $connection, string $kind, string $localId, ?string $externalId): void
    {
        $criteria = ['connection_id' => $connection->id, 'kind' => $kind, 'local_id' => $localId];
        if ($externalId === null || $externalId === '') {
            $this->database->delete(Schema::RESOURCES, $criteria);

            return;
        }
        $now = $this->clock->now();
        if ($this->database->update(Schema::RESOURCES, $criteria, ['external_id' => $externalId, 'updated_at' => $now]) === 0) {
            $this->database->insert(Schema::RESOURCES, ['id' => Uuid::v7()->toRfc4122(), ...$criteria, 'external_id' => $externalId, 'updated_at' => $now]);
        }
    }

    public function forget(Connection $connection, string $kind, string $localId): void
    {
        $this->database->delete(Schema::RESOURCES, ['connection_id' => $connection->id, 'kind' => $kind, 'local_id' => $localId]);
    }

    public function count(Connection $connection, string $kind): int
    {
        return $this->database->count(Schema::RESOURCES, ['connection_id' => $connection->id, 'kind' => $kind]);
    }

    /**
     * `$at` is the creation time of the user the connection created with the membership: written as
     * the provenance's own, it is what {@see createdUser()} recognises.
     */
    public function recordMembership(Connection $connection, string $userId, ?DateTimeImmutable $at = null): void
    {
        if ($this->database->findOne(Schema::PROVENANCE, ['organization_id' => $connection->organizationId, 'user_id' => $userId]) === null) {
            $this->database->insert(Schema::PROVENANCE, ['id' => Uuid::v7()->toRfc4122(), 'organization_id' => $connection->organizationId, 'user_id' => $userId, 'connection_id' => $connection->id, 'created_at' => $at ?? $this->clock->now()]);
        }
    }

    /**
     * Whether the connection created the user (not only the membership): the provenance and the user
     * carry the same creation time, to the second.
     */
    public function createdUser(Connection $connection, string $userId, DateTimeImmutable $userCreatedAt): bool
    {
        $row = $this->database->findOne(Schema::PROVENANCE, ['organization_id' => $connection->organizationId, 'user_id' => $userId, 'connection_id' => $connection->id]);
        $at = $row['created_at'] ?? null;
        if ($at === null) {
            return false;
        }
        $at = $at instanceof DateTimeInterface ? $at : new DateTimeImmutable((string) $at);

        return $at->format(self::SECOND) === $userCreatedAt->format(self::SECOND);
    }

    public function createdMembership(Connection $connection, string $userId): bool
    {
        return $this->database->findOne(Schema::PROVENANCE, ['organization_id' => $connection->organizationId, 'user_id' => $userId, 'connection_id' => $connection->id]) !== null;
    }

    public function forgetMembership(Connection $connection, string $userId): void
    {
        $this->database->delete(Schema::PROVENANCE, ['organization_id' => $connection->organizationId, 'user_id' => $userId]);
    }

    public function provisionedUsers(Connection $connection): int
    {
        return $this->database->count(Schema::PROVENANCE, ['connection_id' => $connection->id]);
    }
}
