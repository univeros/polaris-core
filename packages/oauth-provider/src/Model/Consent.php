<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A user's consent to a client (`polaris_oauth_consent`): the scopes granted so far, and the
 * organization the user was acting in; one row per user and client.
 */
final class Consent
{
    public string $id = '';
    public string $userId = '';
    public string $clientId = '';
    public ?string $organizationId = null;
    /** @var list<string> */
    public array $scopes = [];
    public DateTimeImmutable $grantedAt;
    public DateTimeImmutable $updatedAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'client_id' => $this->clientId,
            'organization_id' => $this->organizationId,
            'scopes' => $this->scopes,
            'granted_at' => $this->grantedAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
