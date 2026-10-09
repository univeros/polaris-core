<?php

declare(strict_types=1);

namespace Polaris\Social\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A linked provider account (`polaris_social_account`): whose it is, which provider and subject, the
 * email the provider reported, the scopes granted, the public profile, and the tokens (encrypted, never
 * in `toArray()`).
 */
final class Account
{
    public string $id = '';
    public string $userId = '';
    public string $provider = '';
    public string $providerAccountId = '';
    public ?string $email = null;
    public bool $emailVerified = false;
    /** @var list<string> */
    public array $scopes = [];
    /** @var array<string, mixed> */
    public array $profile = [];
    public ?string $accessTokenEnc = null;
    public ?string $refreshTokenEnc = null;
    public ?DateTimeImmutable $expiresAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'provider' => $this->provider,
            'provider_account_id' => $this->providerAccountId,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'scopes' => $this->scopes,
            'profile' => $this->profile,
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
