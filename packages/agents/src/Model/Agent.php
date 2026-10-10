<?php

declare(strict_types=1);

namespace Polaris\Agents\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * An agent (`polaris_agent`): its id is the `client_id` of its OAuth client. Who owns it (a user, or an
 * organization through the member who registered it), whether it acts for its owner (`delegated`) or
 * as itself (`autonomous`), how it authenticates, its public key, its status.
 */
final class Agent
{
    public const string OWNER_USER = 'user';
    public const string OWNER_ORGANIZATION = 'organization';

    public const string MODE_DELEGATED = 'delegated';
    public const string MODE_AUTONOMOUS = 'autonomous';
    public const array MODES = [self::MODE_DELEGATED, self::MODE_AUTONOMOUS];

    public const string AUTH_PRIVATE_KEY_JWT = 'private_key_jwt';
    public const string AUTH_CLIENT_SECRET = 'client_secret';
    public const string AUTH_DELEGATED_TOKEN = 'delegated_token';
    public const array AUTHS = [self::AUTH_PRIVATE_KEY_JWT, self::AUTH_CLIENT_SECRET, self::AUTH_DELEGATED_TOKEN];

    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_SUSPENDED = 'suspended';
    public const string STATUS_REVOKED = 'revoked';

    public string $id = '';
    public string $ownerType = self::OWNER_USER;
    public string $ownerId = '';
    public ?string $organizationId = null;
    public string $name = '';
    public string $mode = self::MODE_DELEGATED;
    public ?string $hostId = null;
    public string $auth = self::AUTH_PRIVATE_KEY_JWT;
    /** @var array<string, mixed>|null */
    public ?array $publicJwk = null;
    public string $status = self::STATUS_ACTIVE;
    public string $createdBy = '';
    public ?DateTimeImmutable $sealedAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /**
     * The user the agent acts as or for: its owner, or for an organization's agent the member who
     * registered it.
     */
    public function subject(): string
    {
        return $this->ownerType === self::OWNER_USER ? $this->ownerId : $this->createdBy;
    }

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'owner_type' => $this->ownerType,
            'owner_id' => $this->ownerId,
            'organization_id' => $this->organizationId,
            'name' => $this->name,
            'mode' => $this->mode,
            'host_id' => $this->hostId,
            'auth' => $this->auth,
            'public_jwk' => $this->publicJwk,
            'status' => $this->status,
            'created_by' => $this->createdBy,
            'sealed_at' => $this->sealedAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
