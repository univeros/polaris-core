<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

/**
 * An authorization code (`polaris_oauth_code`): stored as a keyed hash, bound to the client, the
 * redirect URI, the PKCE challenge, the nonce and the DPoP key it was asked with; spent once.
 */
final class Code
{
    public string $id = '';
    public string $codeHash = '';
    public string $clientId = '';
    public string $userId = '';
    public ?string $organizationId = null;
    /** @var list<string> */
    public array $scopes = [];
    public string $redirectUri = '';
    public string $codeChallenge = '';
    public ?string $nonce = null;
    public ?string $resource = null;
    public ?string $dpopJkt = null;
    public ?int $authTime = null;
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $usedAt = null;
    public DateTimeImmutable $createdAt;
}
