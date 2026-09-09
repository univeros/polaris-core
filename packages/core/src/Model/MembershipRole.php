<?php

declare(strict_types=1);

namespace Polaris\Model;

/**
 * Join row binding a {@see Membership} to a {@see Role} (table `auth_membership_roles`).
 *
 * This is what grants a user their roles *within a specific organization*. The composite primary
 * key `(membership_id, role_id)` makes each pairing unique. Both columns are `ON DELETE CASCADE`
 * foreign keys, so removing a membership or a role drops the associated grants automatically.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class MembershipRole
{
    public string $membershipId = '';
    public string $roleId = '';
}
