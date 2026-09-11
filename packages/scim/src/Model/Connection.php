<?php

declare(strict_types=1);

namespace Polaris\Scim\Model;

use DateTimeImmutable;

use function is_array;
use function json_decode;

use const DATE_ATOM;

/**
 * A directory's connection to one organization (`polaris_scim_connection`): the bearer token it
 * provisions with (stored as a keyed hash), what deprovisioning does, its state.
 */
final class Connection
{
    public const string ACTIVE = 'active';
    public const string DECOMMISSIONED = 'decommissioned';
    public const string DEACTIVATE = 'deactivate';
    public const string DELETE = 'delete';

    public string $id = '';
    public string $organizationId = '';
    public ?string $ssoProviderId = null;
    public string $name = '';
    public string $tokenHash = '';
    public string $status = self::ACTIVE;
    /** JSON as stored: `deprovision` (deactivate|delete). */
    public string $settings = '{}';
    public ?DateTimeImmutable $lastSyncAt = null;
    public ?DateTimeImmutable $decommissionedAt = null;
    public ?string $createdBy = null;
    public DateTimeImmutable $createdAt;

    public function deprovision(): string
    {
        $decoded = json_decode($this->settings, true);

        return is_array($decoded) && ($decoded['deprovision'] ?? null) === self::DELETE ? self::DELETE : self::DEACTIVATE;
    }

    public function active(): bool
    {
        return $this->status === self::ACTIVE;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'organization_id' => $this->organizationId,
            'sso_provider_id' => $this->ssoProviderId,
            'name' => $this->name,
            'status' => $this->status,
            'deprovision' => $this->deprovision(),
            'last_sync_at' => $this->lastSyncAt?->format(DATE_ATOM),
            'decommissioned_at' => $this->decommissionedAt?->format(DATE_ATOM),
            'created_by' => $this->createdBy,
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
