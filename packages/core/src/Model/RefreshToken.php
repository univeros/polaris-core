<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A refresh-token session/device record (table `auth_refresh_tokens`).
 *
 * The opaque token is never stored — only its keyed HMAC hash
 * ({@see \Polaris\Security\Pepper}). `familyId` ties a rotation lineage
 * together so that replaying a rotated token can revoke the whole family
 * (theft detection).
 *
 * See `docs/auth/data-model.md` and `docs/auth/flows.md` for the rotation design.
 */
class RefreshToken
{
    /** `revoked_reason` values. */
    public const string REASON_ROTATED = 'rotated';
    public const string REASON_LOGOUT = 'logout';
    public const string REASON_REUSE_DETECTED = 'reuse_detected';
    public const string REASON_ADMIN = 'admin';
    public const string REASON_PASSWORD_CHANGE = 'password_change';
    public string $id = '';
    public string $userId = '';
    public ?string $organizationId = null;
    public string $familyId = '';
    public ?string $parentId = null;

    /** Keyed HMAC-SHA256 (hex) of the opaque token; never the token itself. */
    public string $tokenHash = '';
    public ?string $userAgent = null;
    public ?string $ip = null;

    /** Whether the session's authentication included a second factor; mirrored into refreshed access tokens (#97). */
    public bool $mfa = false;

    /** Comma-joined authentication-method references (e.g. `pwd,otp`); null on pre-#97 rows. */
    public ?string $amr = null;

    /** Unix timestamp of the session's last full authentication (login or step-up). */
    public ?int $authTime = null;
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $lastUsedAt = null;
    public ?DateTimeImmutable $revokedAt = null;

    /** One of `rotated`, `logout`, `reuse_detected`, `admin`, `password_change`. */
    public ?string $revokedReason = null;
    public DateTimeImmutable $createdAt;
}
