<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\Organization;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class OrganizationSchema
{
    public static function define(): Model
    {
        return Model::table('auth_organizations', Organization::class, [
            Field::string('id', 36)->primary(),
            Field::string('name', 160),
            Field::string('slug', 160),
            Field::string('status', 16)->default('active'),
            Field::string('createdBy', 36),
            Field::datetime('createdAt'),
            Field::datetime('updatedAt'),
        ])
            ->unique(['slug'], 'auth_organizations_slug_unique')
            ->index(['status'], 'auth_organizations_status_index');
    }
}
