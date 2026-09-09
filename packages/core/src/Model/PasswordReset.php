<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A single-use password-reset token (table `auth_password_resets`).
 *
 * The emailed token is never stored — only its keyed HMAC-SHA256 hash
 * ({@see \Polaris\Security\Pepper}). A row is consumed exactly once
 * (`consumedAt`) and expires after the configured window (default 1h, shorter than
 * verification by design).
 *
 * Shares its shape with {@see EmailVerification}; see `docs/auth/data-model.md`.
 */
class PasswordReset
{
    public string $id = '';
    public string $userId = '';

    /** The address the reset was requested for. */
    public string $email = '';

    /** Keyed HMAC-SHA256 (hex) of the emailed token; never the token itself. */
    public string $tokenHash = '';
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $consumedAt = null;
    public ?string $ip = null;
    public DateTimeImmutable $createdAt;
}
