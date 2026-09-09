<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\Permission;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class PermissionSchema
{
    public static function define(): Model
    {
        return Model::table('auth_permissions', Permission::class, [
            Field::string('id', 36)->primary(),
            Field::string('key', 120),
            Field::string('description', 255),
        ])
            ->unique(['key'], 'auth_permissions_key_unique');
    }
}
