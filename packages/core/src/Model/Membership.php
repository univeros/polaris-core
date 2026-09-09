<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * Binds one user to one organization (table `auth_memberships`).
 *
 * The `unique(user_id, organization_id)` constraint guarantees a user joins a given organization
 * at most once. A membership starts {@see self::STATUS_INVITED} and becomes {@see self::STATUS_ACTIVE}
 * once accepted (or immediately, for the creator of an organization); {@see $joinedAt} records when.
 * A membership carries the user's org-scoped roles via `auth_membership_roles`.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class Membership
{
    /** `status` values. */
    public const string STATUS_INVITED = 'invited';
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_SUSPENDED = 'suspended';
    public string $id = '';
    public string $userId = '';
    public string $organizationId = '';

    /** One of `invited`, `active`, `suspended`. */
    public string $status = 'invited';

    /** The user who issued the invitation, when the membership originated from one. */
    public ?string $invitedBy = null;

    /** When the membership became active; null while still invited. */
    public ?DateTimeImmutable $joinedAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;
}
