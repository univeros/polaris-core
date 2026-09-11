<?php

declare(strict_types=1);

namespace Polaris\Audit\Drain;

use Polaris\Audit\Model\AuditDrain;
use Polaris\Audit\Schema;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The per-organization drains: created and listed by the admin and organization routes, read by
 * {@see DrainSink} at delivery time. The signing secret is encrypted at rest and never returned.
 */
final class Drains
{
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly EncrypterInterface $encrypter,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string> $filter
     */
    public function create(string $organizationId, string $endpoint, #[\SensitiveParameter] string $secret, array $filter = [], ?string $createdBy = null): AuditDrain
    {
        $drain = new AuditDrain();
        $drain->id = Uuid::v7()->toRfc4122();
        $drain->organizationId = $organizationId;
        $drain->endpoint = $endpoint;
        $drain->secret = $secret;
        $drain->filter = $filter;
        $drain->createdAt = $this->clock->now();
        $drain->createdBy = $createdBy;
        $this->database->insert(Schema::DRAINS, [
            'id' => $drain->id,
            'organization_id' => $drain->organizationId,
            'type' => $drain->type,
            'endpoint' => $drain->endpoint,
            'secret' => $this->encrypter->encrypt($secret),
            'filter' => json_encode($drain->filter, JSON_THROW_ON_ERROR),
            'status' => $drain->status,
            'last_delivery_at' => null,
            'last_error' => null,
            'created_at' => $drain->createdAt,
            'created_by' => $createdBy,
        ]);

        return $drain;
    }

    public function find(string $id): ?AuditDrain
    {
        $row = $this->database->findOne(Schema::DRAINS, ['id' => $id]);

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @return list<AuditDrain>
     */
    public function forOrganization(string $organizationId, bool $activeOnly = false): array
    {
        $criteria = ['organization_id' => $organizationId, ...($activeOnly ? ['status' => AuditDrain::STATUS_ACTIVE] : [])];
        $drains = [];
        foreach ($this->database->findMany(Schema::DRAINS, $criteria, ['id' => 'asc']) as $row) {
            $drains[] = $this->hydrate($row);
        }

        return $drains;
    }

    public function setStatus(string $id, string $status): void
    {
        $this->database->update(Schema::DRAINS, ['id' => $id], ['status' => $status]);
    }

    public function delete(string $id): bool
    {
        return $this->database->delete(Schema::DRAINS, ['id' => $id]) > 0;
    }

    public function recordDelivery(string $id, ?string $error): void
    {
        $this->database->update(Schema::DRAINS, ['id' => $id], ['last_delivery_at' => $this->clock->now(), 'last_error' => $error]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): AuditDrain
    {
        $drain = new AuditDrain();
        $drain->id = (string) $row['id'];
        $drain->organizationId = (string) $row['organization_id'];
        $drain->type = (string) $row['type'];
        $drain->endpoint = (string) $row['endpoint'];
        $drain->secret = (string) $this->encrypter->decrypt((string) $row['secret']);
        $filter = $row['filter'] ?? [];
        $decoded = is_string($filter) ? json_decode($filter, true) : $filter;
        $drain->filter = is_array($decoded) ? array_values($decoded) : [];
        $drain->status = (string) $row['status'];
        $last = $row['last_delivery_at'] ?? null;
        $drain->lastDeliveryAt = $last instanceof \DateTimeImmutable ? $last : (is_string($last) && $last !== '' ? new \DateTimeImmutable($last) : null);
        $drain->lastError = is_string($row['last_error'] ?? null) && $row['last_error'] !== '' ? $row['last_error'] : null;
        $created = $row['created_at'];
        $drain->createdAt = $created instanceof \DateTimeImmutable ? $created : new \DateTimeImmutable((string) $created);
        $drain->createdBy = is_string($row['created_by'] ?? null) && $row['created_by'] !== '' ? $row['created_by'] : null;

        return $drain;
    }
}
