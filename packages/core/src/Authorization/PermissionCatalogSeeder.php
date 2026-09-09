<?php

declare(strict_types=1);

namespace Polaris\Authorization;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * Makes sure every catalog permission and every system role template exists, with its grants.
 * Idempotent: rows are looked up by their natural keys and only created when missing.
 */
final readonly class PermissionCatalogSeeder
{
    public function __construct(private PermissionCatalog $catalog)
    {
    }

    public function seed(DatabaseAdapter $database, DateTimeImmutable $now): void
    {
        $permissionIds = [];
        foreach ($this->catalog->permissions() as $key => $description) {
            $permissionIds[$key] = $this->ensurePermission($database, $key, $description);
        }

        foreach ($this->catalog->roleTemplates() as $template) {
            $roleId = $this->ensureSystemRole($database, $template, $now);
            foreach ($template->permissionKeys as $key) {
                $permissionId = $permissionIds[$key] ?? null;
                if ($permissionId !== null) {
                    $this->ensureRolePermission($database, $roleId, $permissionId);
                }
            }
        }
    }

    private function ensurePermission(DatabaseAdapter $database, string $key, string $description): string
    {
        $row = $database->findOne('auth_permissions', ['key' => $key]);
        if ($row !== null && is_string($id = $row['id'] ?? null)) {
            return $id;
        }

        $id = Uuid::v7()->toRfc4122();
        $database->insert('auth_permissions', ['id' => $id, 'key' => $key, 'description' => $description]);

        return $id;
    }

    private function ensureSystemRole(DatabaseAdapter $database, RoleTemplate $template, DateTimeImmutable $now): string
    {
        $row = $database->findOne('auth_roles', ['slug' => $template->slug, 'organization_id' => null]);
        if ($row !== null && is_string($id = $row['id'] ?? null)) {
            return $id;
        }

        $id = Uuid::v7()->toRfc4122();
        $database->insert('auth_roles', [
            'id' => $id,
            'organization_id' => null,
            'name' => $template->name,
            'slug' => $template->slug,
            'description' => $template->description,
            'is_system' => true,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        return $id;
    }

    private function ensureRolePermission(DatabaseAdapter $database, string $roleId, string $permissionId): void
    {
        if ($database->count('auth_role_permissions', ['role_id' => $roleId, 'permission_id' => $permissionId]) === 0) {
            $database->insert('auth_role_permissions', ['role_id' => $roleId, 'permission_id' => $permissionId]);
        }
    }
}
