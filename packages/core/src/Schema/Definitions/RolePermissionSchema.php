<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\RolePermission;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class RolePermissionSchema
{
    public static function define(): Model
    {
        return Model::table('auth_role_permissions', RolePermission::class, [
            Field::string('roleId', 36)->primary(),
            Field::string('permissionId', 36)->primary(),
        ])
            ->references(['role_id'], 'auth_roles', ['id'])
            ->references(['permission_id'], 'auth_permissions', ['id']);
    }
}
