<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\Membership;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class MembershipSchema
{
    public static function define(): Model
    {
        return Model::table('auth_memberships', Membership::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('organizationId', 36),
            Field::string('status', 16)->default('invited'),
            Field::string('invitedBy', 36)->nullable(),
            Field::datetime('joinedAt')->nullable(),
            Field::datetime('createdAt'),
            Field::datetime('updatedAt'),
        ])
            ->unique(['user_id', 'organization_id'], 'auth_memberships_user_org_unique')
            ->index(['organization_id', 'status'], 'auth_memberships_org_status_index');
    }
}
