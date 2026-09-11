<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

/**
 * Who calls an admin route: an admin user (a Polaris user with a grant, or a superadmin) or an API
 * key, with a role and a scope (`instance`, or one organization id).
 */
final readonly class Principal
{
    public const string TYPE_USER = 'user';
    public const string TYPE_API_KEY = 'api_key';
    public const string SCOPE_INSTANCE = 'instance';

    public function __construct(
        public string $id,
        public string $type,
        public Role $role,
        public string $scope = self::SCOPE_INSTANCE,
    ) {
    }

    public function allows(Capability $capability): bool
    {
        return $this->role->allows($capability);
    }

    /**
     * Instance-scoped principals see every organization; an organization-scoped one sees its own.
     */
    public function covers(?string $organizationId): bool
    {
        return $this->scope === self::SCOPE_INSTANCE || ($organizationId !== null && $this->scope === $organizationId);
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return ['id' => $this->id, 'type' => $this->type, 'role' => $this->role->value, 'scope' => $this->scope];
    }
}
