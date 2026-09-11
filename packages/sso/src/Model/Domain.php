<?php

declare(strict_types=1);

namespace Polaris\Sso\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A domain an organization claims for SSO routing (`polaris_sso_domain`): once verified, a sign-in with
 * an email of that domain goes to the domain's provider.
 */
final class Domain
{
    public const string RECORD = '_polaris';
    public const string WELL_KNOWN = '/.well-known/polaris-sso.txt';

    public string $id = '';
    public string $organizationId = '';
    public string $providerId = '';
    public string $domain = '';
    public string $token = '';
    public ?DateTimeImmutable $verifiedAt = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'organization_id' => $this->organizationId,
            'provider_id' => $this->providerId,
            'domain' => $this->domain,
            'verification' => [
                'token' => $this->token,
                'dns' => ['record' => self::RECORD . '.' . $this->domain, 'type' => 'TXT', 'value' => $this->token],
                'https' => ['url' => 'https://' . $this->domain . self::WELL_KNOWN, 'body' => $this->token],
            ],
            'verified' => $this->verifiedAt !== null,
            'verified_at' => $this->verifiedAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
