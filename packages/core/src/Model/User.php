<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * The identity record of Polaris (table `auth_users`).
 *
 * Nothing here is database-specific. The UUID v7 primary key is assigned by the application
 * (never auto-incremented), so identifiers stay opaque and portable.
 *
 * See `docs/auth/data-model.md` for the full field reference.
 */
class User
{
    /** `status` values. */
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_DISABLED = 'disabled';
    public const string STATUS_LOCKED = 'locked';
    public string $id = '';
    public string $email = '';
    public ?DateTimeImmutable $emailVerifiedAt = null;
    public ?string $passwordHash = null;
    public ?string $displayName = null;

    /** One of `active`, `disabled`, `locked`. */
    public string $status = 'active';
    public bool $mfaEnforced = false;
    public int $failedLoginCount = 0;

    /** When the most recent failed login occurred; anchors the lockout failure window. */
    public ?DateTimeImmutable $failedLoginAt = null;
    public ?DateTimeImmutable $lockedUntil = null;
    public ?DateTimeImmutable $lastLoginAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;
}
