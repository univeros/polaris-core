<?php

declare(strict_types=1);

namespace Polaris\Admin\Model;

use DateTimeImmutable;

/**
 * An API key for a dashboard or an integration (`polaris_admin_key`): hashed at rest, shown once at
 * creation, with a role, a scope, an optional IP allowlist and an optional expiry.
 */
final class AdminKey
{
    public string $id = '';
    public string $name = '';
    public string $keyHash = '';
    public string $role = 'viewer';
    public string $scope = 'instance';
    /** @var list<string> CIDR blocks or addresses; empty means anywhere */
    public array $ipAllowlist = [];
    public ?DateTimeImmutable $expiresAt = null;
    public ?DateTimeImmutable $lastUsedAt = null;
    public ?string $createdBy = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'role' => $this->role,
            'scope' => $this->scope,
            'ip_allowlist' => $this->ipAllowlist,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'last_used_at' => $this->lastUsedAt?->format(DATE_ATOM),
            'created_by' => $this->createdBy,
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
