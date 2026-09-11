<?php

declare(strict_types=1);

namespace Polaris\Audit\Model;

use DateTimeImmutable;

use function str_ends_with;
use function str_starts_with;
use function substr;

use const DATE_ATOM;

/**
 * A per-organization delivery target configured at runtime (`polaris_audit_drain`): the organization's
 * events matching `filter` are posted to `endpoint`, signed with `secret` (encrypted at rest).
 */
final class AuditDrain
{
    public const string TYPE_WEBHOOK = 'webhook';
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_PAUSED = 'paused';

    public string $id = '';
    public string $organizationId = '';
    public string $type = self::TYPE_WEBHOOK;
    public string $endpoint = '';
    public string $secret = '';
    /** @var list<string> event names or `prefix.*` patterns; empty means every event */
    public array $filter = [];
    public string $status = self::STATUS_ACTIVE;
    public ?DateTimeImmutable $lastDeliveryAt = null;
    public ?string $lastError = null;
    public DateTimeImmutable $createdAt;
    public ?string $createdBy = null;

    public function accepts(string $name): bool
    {
        if ($this->filter === []) {
            return true;
        }
        foreach ($this->filter as $pattern) {
            if ($pattern === $name || (str_ends_with($pattern, '.*') && str_starts_with($name, substr($pattern, 0, -1)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'organization_id' => $this->organizationId,
            'type' => $this->type,
            'endpoint' => $this->endpoint,
            'filter' => $this->filter,
            'status' => $this->status,
            'last_delivery_at' => $this->lastDeliveryAt?->format(DATE_ATOM),
            'last_error' => $this->lastError,
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
