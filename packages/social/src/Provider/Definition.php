<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Closure;

/**
 * What makes a provider: its endpoints, the scopes to ask for, how it wants the client authenticated at
 * the token endpoint, whether it does PKCE and OpenID Connect, its quirks, and how its profile maps to
 * a {@see Profile}. The {@see Catalog} holds one per known provider; a host passes its own for any
 * other OAuth 2 server (`GenericOAuth`).
 */
final readonly class Definition
{
    public const string AUTH_POST = 'post';
    public const string AUTH_BASIC = 'basic';

    /** @var Closure(array<string, mixed>): Profile */
    public Closure $profile;

    /**
     * @param list<string> $scopes the default scopes
     * @param string|null $userinfoEndpoint null when the profile is in the id_token or the token response
     * @param string|null $issuer the OpenID Connect issuer, exact, or a regular expression (`#...#`) when it varies (Microsoft's tenants)
     * @param string|null $jwksUri the key set, when the issuer has no discovery document
     * @param array<string, string> $authorizationParams extra query parameters of the authorization request
     * @param array<string, string> $userinfoHeaders extra headers of the profile request
     * @param callable(array<string, mixed>): Profile $profile the userinfo (or id_token claims, or token response) to a profile
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public ?string $userinfoEndpoint,
        public array $scopes,
        callable $profile,
        public bool $pkce = true,
        public ?string $issuer = null,
        public ?string $jwksUri = null,
        public string $tokenAuth = self::AUTH_POST,
        public array $authorizationParams = [],
        public string $clientIdParam = 'client_id',
        public string $userinfoMethod = 'GET',
        public array $userinfoHeaders = [],
        public bool $profileInTokenResponse = false,
        public bool $formPost = false,
        public string $scopeSeparator = ' ',
    ) {
        $this->profile = $profile(...);
    }

    public function oidc(): bool
    {
        return $this->issuer !== null;
    }
}
