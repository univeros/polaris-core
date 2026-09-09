<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A named bundle of permissions, scoped to an organization (table `auth_roles`).
 *
 * A role belongs to one organization, or is a **system role** when {@see $organizationId} is null
 * (e.g. the global `superadmin`, or the `owner`/`admin`/`member` templates cloned into each org).
 * {@see $slug} is unique within its organization (`unique(organization_id, slug)`). System roles
 * ({@see $isSystem}) cannot be edited or deleted by tenants. A role's permissions are bound via
 * `auth_role_permissions`; a membership's roles via `auth_membership_roles`.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class Role
{
    public string $id = '';

    /** Owning organization; null marks a system/global role. */
    public ?string $organizationId = null;
    public string $name = '';

    /** URL-safe; unique within the owning organization. */
    public string $slug = '';
    public ?string $description = null;

    /** System roles cannot be deleted or edited by tenants. */
    public bool $isSystem = false;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;
}
