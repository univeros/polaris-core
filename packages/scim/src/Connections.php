<?php

declare(strict_types=1);

namespace Polaris\Scim;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Scim\Model\Connection;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_slice;
use function base64_encode;
use function count;
use function is_string;
use function json_encode;
use function max;
use function min;
use function random_bytes;
use function rtrim;
use function str_starts_with;
use function strtr;

use const JSON_THROW_ON_ERROR;

/**
 * The organizations' connections (`polaris_scim_connection`) and their tokens: `pst_` and 256 random
 * bits, stored as a keyed hash, shown once at creation and rotation.
 */
final class Connections
{
    public const string PREFIX = 'pst_';
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;
    private const string PEPPER_CONTEXT = 'scim_token';

    public function __construct(private readonly DatabaseAdapter $database, private readonly Pepper $pepper, private readonly ClockInterface $clock)
    {
    }

    /**
     * @return array{Connection, string} the connection and its token, in clear
     */
    public function create(string $organizationId, string $name, string $deprovision, ?string $ssoProviderId, ?string $createdBy): array
    {
        $token = self::token();
        $connection = new Connection();
        $connection->id = Uuid::v7()->toRfc4122();
        $connection->organizationId = $organizationId;
        $connection->ssoProviderId = $ssoProviderId;
        $connection->name = $name;
        $connection->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        $connection->settings = json_encode(['deprovision' => $deprovision], JSON_THROW_ON_ERROR);
        $connection->createdBy = $createdBy;
        $connection->createdAt = $this->clock->now();
        $this->database->insert(Schema::CONNECTIONS, [
            'id' => $connection->id,
            'organization_id' => $organizationId,
            'sso_provider_id' => $ssoProviderId,
            'name' => $name,
            'token_hash' => $connection->tokenHash,
            'status' => Connection::ACTIVE,
            'settings' => $connection->settings,
            'last_sync_at' => null,
            'decommissioned_at' => null,
            'created_by' => $createdBy,
            'created_at' => $connection->createdAt,
        ]);

        return [$connection, $token];
    }

    /**
     * A new token; the previous one stops at once.
     */
    public function rotate(Connection $connection): string
    {
        $token = self::token();
        $connection->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        $this->database->update(Schema::CONNECTIONS, ['id' => $connection->id], ['token_hash' => $connection->tokenHash]);

        return $token;
    }

    public function decommission(Connection $connection): Connection
    {
        $connection->status = Connection::DECOMMISSIONED;
        $connection->decommissionedAt = $this->clock->now();
        $this->database->update(Schema::CONNECTIONS, ['id' => $connection->id], ['status' => $connection->status, 'decommissioned_at' => $connection->decommissionedAt]);

        return $connection;
    }

    public function touch(Connection $connection): void
    {
        $connection->lastSyncAt = $this->clock->now();
        $this->database->update(Schema::CONNECTIONS, ['id' => $connection->id], ['last_sync_at' => $connection->lastSyncAt]);
    }

    /**
     * The active connection a token belongs to; null otherwise.
     */
    public function authenticate(#[SensitiveParameter] ?string $token): ?Connection
    {
        if ($token === null || !str_starts_with($token, self::PREFIX)) {
            return null;
        }
        $row = $this->database->findOne(Schema::CONNECTIONS, ['token_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $token)]);
        $connection = $row === null ? null : self::hydrate($row);

        return $connection?->active() === true ? $connection : null;
    }

    public function find(string $id): ?Connection
    {
        $row = $this->database->findOne(Schema::CONNECTIONS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Connection>
     */
    public function forOrganization(string $organizationId): array
    {
        $connections = [];
        foreach ($this->database->findMany(Schema::CONNECTIONS, ['organization_id' => $organizationId], ['id' => 'asc']) as $row) {
            $connections[] = self::hydrate($row);
        }

        return $connections;
    }

    /**
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function list(?string $organizationId = null, ?string $cursor = null, int $limit = self::DEFAULT_LIMIT): array
    {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $criteria = [];
        if ($organizationId !== null) {
            $criteria['organization_id'] = $organizationId;
        }
        if ($cursor !== null) {
            $criteria['id'] = Condition::gt($cursor);
        }
        $rows = $this->database->findMany(Schema::CONNECTIONS, $criteria, ['id' => 'asc'], $limit + 1);
        $data = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            $data[] = self::hydrate($row)->toArray();
        }

        return ['data' => $data, 'next_cursor' => count($rows) > $limit && $data !== [] ? $data[count($data) - 1]['id'] : null];
    }

    public function delete(string $id): bool
    {
        $this->database->delete(Schema::RESOURCES, ['connection_id' => $id]);
        $this->database->delete(Schema::PROVENANCE, ['connection_id' => $id]);

        return $this->database->delete(Schema::CONNECTIONS, ['id' => $id]) > 0;
    }

    private static function token(): string
    {
        return self::PREFIX . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Connection
    {
        $connection = new Connection();
        $connection->id = (string) $row['id'];
        $connection->organizationId = (string) $row['organization_id'];
        $connection->ssoProviderId = is_string($row['sso_provider_id'] ?? null) && $row['sso_provider_id'] !== '' ? $row['sso_provider_id'] : null;
        $connection->name = (string) $row['name'];
        $connection->tokenHash = (string) $row['token_hash'];
        $connection->status = (string) $row['status'];
        $connection->settings = is_string($row['settings']) ? $row['settings'] : json_encode($row['settings'], JSON_THROW_ON_ERROR);
        $connection->lastSyncAt = self::datetime($row['last_sync_at'] ?? null);
        $connection->decommissionedAt = self::datetime($row['decommissioned_at'] ?? null);
        $connection->createdBy = is_string($row['created_by'] ?? null) && $row['created_by'] !== '' ? $row['created_by'] : null;
        $connection->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $connection;
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
