<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

/**
 * An issued token (`polaris_oauth_token`): an access token by its `jti` (the JWT itself is not
 * stored), or a refresh token by its keyed hash, in a rotation family; whose, for which client, with
 * which scopes, resource and DPoP key, and the actor it carries after a token exchange.
 */
final class Token
{
    public const string KIND_ACCESS = 'access';
    public const string KIND_REFRESH = 'refresh';

    public string $id = '';
    public string $kind = self::KIND_ACCESS;
    public ?string $tokenHash = null;
    public string $clientId = '';
    public ?string $userId = null;
    public ?string $organizationId = null;
    /** @var list<string> */
    public array $scopes = [];
    public ?string $familyId = null;
    public ?string $resource = null;
    public ?string $dpopJkt = null;
    /** @var array<string, mixed>|null the `act` claim of an exchanged token */
    public ?array $actor = null;
    public ?int $authTime = null;
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $revokedAt = null;
    public DateTimeImmutable $createdAt;

    public function isLive(DateTimeImmutable $now): bool
    {
        return $this->revokedAt === null && $this->expiresAt > $now;
    }
}
