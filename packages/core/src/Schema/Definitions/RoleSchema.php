<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\Role;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class RoleSchema
{
    public static function define(): Model
    {
        return Model::table('auth_roles', Role::class, [
            Field::string('id', 36)->primary(),
            Field::string('organizationId', 36)->nullable(),
            Field::string('name', 80),
            Field::string('slug', 80),
            Field::string('description', 255)->nullable(),
            Field::bool('isSystem')->default(false),
            Field::datetime('createdAt'),
            Field::datetime('updatedAt'),
        ])
            ->unique(['organization_id', 'slug'], 'auth_roles_org_slug_unique');
    }
}
