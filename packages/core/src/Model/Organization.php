<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A tenant in the multi-tenant model (table `auth_organizations`).
 *
 * Every organization is created by a user — {@see $createdBy} — who becomes its owner via an
 * active {@see Membership} granted the org-scoped `owner` role. The {@see $slug} is unique and
 * URL-safe, derived from the name when not supplied.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class Organization
{
    /** `status` values. */
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_SUSPENDED = 'suspended';
    public string $id = '';
    public string $name = '';

    /** URL-safe, unique within the deployment. */
    public string $slug = '';

    /** One of `active`, `suspended`. */
    public string $status = 'active';

    /** The user who created the organization; becomes its owner. */
    public string $createdBy = '';
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;
}
