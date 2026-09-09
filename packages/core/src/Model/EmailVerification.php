<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A single-use email-verification token (table `auth_email_verifications`).
 *
 * The emailed token is never stored — only its keyed HMAC-SHA256 hash
 * ({@see \Polaris\Security\Pepper}). A row is consumed exactly once
 * (`consumedAt`) and expires after the configured window (default 24h). Columns use
 *
 * Shares its shape with {@see PasswordReset}; see `docs/auth/data-model.md`.
 */
class EmailVerification
{
    public string $id = '';
    public string $userId = '';

    /** The address being verified (stored even if the user later changes it). */
    public string $email = '';

    /** Keyed HMAC-SHA256 (hex) of the emailed token; never the token itself. */
    public string $tokenHash = '';
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $consumedAt = null;
    public ?string $ip = null;
    public DateTimeImmutable $createdAt;
}
