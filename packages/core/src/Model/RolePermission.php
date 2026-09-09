<?php

declare(strict_types=1);

namespace Polaris\Model;

/**
 * Join row binding a {@see Role} to a {@see Permission} (table `auth_role_permissions`).
 *
 * The composite primary key `(role_id, permission_id)` makes each pairing unique. Both columns are
 * `ON DELETE CASCADE` foreign keys, so deleting a role or a permission removes its grants
 * automatically — there is no such thing as an orphaned grant.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class RolePermission
{
    public string $roleId = '';
    public string $permissionId = '';
}
