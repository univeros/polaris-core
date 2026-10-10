<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * An API key (`polaris_api_key`): who owns it (a user, or an organization through the member who
 * created it), the organization it acts in, the permissions its owner delegated, its rate limit,
 * expiry, rotation and revocation state. The secret is never stored; `hint` is its last four characters.
 */
final class ApiKey
{
    public const string OWNER_USER = 'user';
    public const string OWNER_ORGANIZATION = 'organization';

    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_ROTATED = 'rotated';
    public const string STATUS_EXPIRED = 'expired';
    public const string STATUS_REVOKED = 'revoked';

    public string $id = '';
    public string $ownerType = self::OWNER_USER;
    public string $ownerId = '';
    public ?string $organizationId = null;
    public string $createdBy = '';
    public string $name = '';
    public string $environment = 'live';
    public string $hint = '';
    public string $keyHash = '';
    /** @var list<string> */
    public array $permissions = [];
    public ?int $rateLimitWindow = null;
    public ?int $rateLimitMax = null;
    /** @var array<string, mixed> */
    public array $metadata = [];
    public ?string $rotatedFromId = null;
    public ?DateTimeImmutable $graceUntil = null;
    public ?DateTimeImmutable $expiresAt = null;
    public ?DateTimeImmutable $lastUsedAt = null;
    public ?DateTimeImmutable $revokedAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /**
     * The user the key acts as: its owner, or for an organization's key the member who created it.
     */
    public function subject(): string
    {
        return $this->ownerType === self::OWNER_USER ? $this->ownerId : $this->createdBy;
    }

    public function status(DateTimeImmutable $now): string
    {
        return match (true) {
            $this->revokedAt !== null => self::STATUS_REVOKED,
            $this->expiresAt !== null && $this->expiresAt <= $now => self::STATUS_EXPIRED,
            $this->graceUntil !== null => self::STATUS_ROTATED,
            default => self::STATUS_ACTIVE,
        };
    }

    /**
     * @return array{window: int, max: int}|null
     */
    public function rateLimit(): ?array
    {
        return $this->rateLimitWindow === null || $this->rateLimitMax === null ? null : ['window' => $this->rateLimitWindow, 'max' => $this->rateLimitMax];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(DateTimeImmutable $now): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'owner_type' => $this->ownerType,
            'owner_id' => $this->ownerId,
            'organization_id' => $this->organizationId,
            'created_by' => $this->createdBy,
            'environment' => $this->environment,
            'hint' => $this->hint,
            'permissions' => $this->permissions,
            'rate_limit' => $this->rateLimit(),
            'metadata' => (object) $this->metadata,
            'status' => $this->status($now),
            'rotated_from' => $this->rotatedFromId,
            'grace_until' => $this->graceUntil?->format(DATE_ATOM),
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'last_used_at' => $this->lastUsedAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
