<?php

declare(strict_types=1);

namespace Polaris\Sso\Model;

use DateTimeImmutable;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;

use const DATE_ATOM;

/**
 * A SAML 2.0 or OIDC identity provider of one organization (`polaris_sso_provider`). `config` holds the
 * protocol settings (SAML: `sso_url`, `slo_url`, `certificate`, `idp_initiated`; OIDC: `issuer`,
 * `client_id`, `client_secret` encrypted at rest, `scopes`); `attributes` maps `email` and `name` onto
 * the provider's claim or attribute names; `jit` holds `enabled` and `roles` (slugs of the organization's
 * roles a provisioned member gets); `redirectUris` the application URLs a sign-in may end on.
 */
final class Provider
{
    public const string SAML = 'saml';
    public const string OIDC = 'oidc';
    public const string SECRET = 'client_secret';

    public string $id = '';
    public string $organizationId = '';
    public string $type = self::OIDC;
    public string $name = '';
    public string $issuer = '';
    /** JSON objects and lists as stored; see the accessors. */
    public string $config = '{}';
    public string $attributes = '{}';
    public string $jit = '{}';
    public string $redirectUris = '[]';
    public bool $enabled = true;
    public ?string $createdBy = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /**
     * @return array<string, mixed>
     */
    public function config(): array
    {
        return self::object($this->config);
    }

    public function setting(string $key): ?string
    {
        $value = $this->config()[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function flag(string $key): bool
    {
        return ($this->config()[$key] ?? false) === true;
    }

    /**
     * The claim or attribute name carrying `$field` (`email`, `name`); the field's own name by default.
     */
    public function attribute(string $field): string
    {
        $value = self::object($this->attributes)[$field] ?? null;

        return is_string($value) && $value !== '' ? $value : $field;
    }

    public function jitEnabled(): bool
    {
        return (self::object($this->jit)['enabled'] ?? false) === true;
    }

    /**
     * @return list<string>
     */
    public function jitRoles(): array
    {
        $roles = self::object($this->jit)['roles'] ?? null;

        return is_array($roles) ? array_values(array_filter($roles, is_string(...))) : [];
    }

    /**
     * @return list<string>
     */
    public function redirectUris(): array
    {
        $decoded = json_decode($this->redirectUris, true);

        return is_array($decoded) ? array_values(array_filter($decoded, is_string(...))) : [];
    }

    /**
     * The provider for the API: the configuration without the secret, and whether one is set.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $config = $this->config();
        $secretSet = isset($config[self::SECRET]) && $config[self::SECRET] !== '';
        unset($config[self::SECRET]);
        if ($this->type === self::OIDC) {
            $config['client_secret_set'] = $secretSet;
        }

        return [
            'id' => $this->id,
            'organization_id' => $this->organizationId,
            'type' => $this->type,
            'name' => $this->name,
            'issuer' => $this->issuer,
            'config' => $config,
            'attributes' => self::object($this->attributes),
            'jit' => ['enabled' => $this->jitEnabled(), 'roles' => $this->jitRoles()],
            'redirect_uris' => $this->redirectUris(),
            'enabled' => $this->enabled,
            'created_by' => $this->createdBy,
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function object(string $json): array
    {
        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }
}
