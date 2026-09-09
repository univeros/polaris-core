<?php

declare(strict_types=1);

namespace Polaris\Model;

/**
 * A single, fine-grained capability in the permission catalog (table `auth_permissions`).
 *
 * Permissions are the atoms of authorization — e.g. `members.invite`, `roles.manage` — referenced
 * by {@see $key} ({@see $key} is unique). The catalog is the single source of truth seeded from a
 * code-defined registry on migrate (see #30); roles aggregate permissions via `auth_role_permissions`.
 * This is a static reference table, so it carries no timestamps.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class Permission
{
    public string $id = '';

    /** Stable, unique catalog key, e.g. `members.invite`. */
    public string $key = '';
    public string $description = '';
}
