<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use SensitiveParameter;

/**
 * What a token endpoint answered: the access token and its lifetime, the refresh token when one came,
 * the scopes granted, the id_token when the provider is OpenID Connect, and the raw body for a
 * provider whose profile travels with it (Notion).
 */
final readonly class Tokens
{
    /**
     * @param list<string> $scopes
     * @param array<string, mixed> $raw
     */
    public function __construct(
        #[SensitiveParameter] public string $accessToken,
        #[SensitiveParameter] public ?string $refreshToken = null,
        public ?int $expiresIn = null,
        public array $scopes = [],
        #[SensitiveParameter] public ?string $idToken = null,
        public array $raw = [],
    ) {
    }
}
