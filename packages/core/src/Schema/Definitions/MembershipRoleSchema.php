<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\MembershipRole;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class MembershipRoleSchema
{
    public static function define(): Model
    {
        return Model::table('auth_membership_roles', MembershipRole::class, [
            Field::string('membershipId', 36)->primary(),
            Field::string('roleId', 36)->primary(),
        ])
            ->references(['membership_id'], 'auth_memberships', ['id'])
            ->references(['role_id'], 'auth_roles', ['id']);
    }
}
