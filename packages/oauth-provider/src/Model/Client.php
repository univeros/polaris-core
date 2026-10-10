<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

use function in_array;

use const DATE_ATOM;

/**
 * A registered client (`polaris_oauth_client`), or one described by its client ID metadata document
 * (`$id` empty, nothing stored): what it is called, how it authenticates at the token endpoint, where
 * it may be sent back to, which grants and scopes it may use, whether its tokens are DPoP-bound and
 * whether its users are asked for consent.
 */
final class Client
{
    public const string TYPE_CONFIDENTIAL = 'confidential';
    public const string TYPE_PUBLIC = 'public';

    public const string AUTH_SECRET_BASIC = 'client_secret_basic';
    public const string AUTH_SECRET_POST = 'client_secret_post';
    public const string AUTH_PRIVATE_KEY_JWT = 'private_key_jwt';
    public const string AUTH_NONE = 'none';

    public string $id = '';
    public string $clientId = '';
    public ?string $organizationId = null;
    public string $name = '';
    public string $type = self::TYPE_CONFIDENTIAL;
    public ?string $secretHash = null;
    /** @var list<string> */
    public array $redirectUris = [];
    /** @var list<string> */
    public array $grantTypes = [];
    /** @var list<string> empty: any scope the server knows */
    public array $scopes = [];
    public string $tokenEndpointAuthMethod = self::AUTH_SECRET_BASIC;
    /** @var array<string, mixed>|null */
    public ?array $jwks = null;
    public ?string $jwksUri = null;
    public bool $dpopBound = false;
    public bool $trusted = false;
    public ?string $logoUri = null;
    public ?string $clientUri = null;
    public ?string $policyUri = null;
    public ?string $tosUri = null;
    public ?string $createdBy = null;
    public ?DateTimeImmutable $disabledAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /** True for a client known by its metadata document rather than a registration. */
    public function isMetadataClient(): bool
    {
        return $this->id === '';
    }

    public function allowsGrant(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    public function allowsRedirect(string $uri): bool
    {
        return in_array($uri, $this->redirectUris, true);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'client_id' => $this->clientId,
            'organization_id' => $this->organizationId,
            'name' => $this->name,
            'type' => $this->type,
            'redirect_uris' => $this->redirectUris,
            'grant_types' => $this->grantTypes,
            'scopes' => $this->scopes,
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            'jwks' => $this->jwks,
            'jwks_uri' => $this->jwksUri,
            'dpop_bound_access_tokens' => $this->dpopBound,
            'trusted' => $this->trusted,
            'logo_uri' => $this->logoUri,
            'client_uri' => $this->clientUri,
            'policy_uri' => $this->policyUri,
            'tos_uri' => $this->tosUri,
            'created_by' => $this->createdBy,
            'disabled_at' => $this->disabledAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }

    /**
     * What a consent screen or a device page shows about the client.
     *
     * @return array<string, mixed>
     */
    public function toPublicArray(): array
    {
        return [
            'client_id' => $this->clientId,
            'name' => $this->name,
            'logo_uri' => $this->logoUri,
            'client_uri' => $this->clientUri,
            'policy_uri' => $this->policyUri,
            'tos_uri' => $this->tosUri,
            'trusted' => $this->trusted,
        ];
    }
}
