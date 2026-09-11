<?php

declare(strict_types=1);

namespace Polaris\Admin\Model;

use DateTimeImmutable;

/**
 * A Polaris user's operator role (`polaris_admin_grant`), on the instance or one organization,
 * optionally expiring.
 */
final class AdminGrant
{
    public string $id = '';
    public string $userId = '';
    public string $role = 'viewer';
    public string $scope = 'instance';
    public ?string $grantedBy = null;
    public ?DateTimeImmutable $expiresAt = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'role' => $this->role,
            'scope' => $this->scope,
            'granted_by' => $this->grantedBy,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
