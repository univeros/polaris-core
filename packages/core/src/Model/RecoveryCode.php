<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A single-use MFA recovery code (table `auth_recovery_codes`).
 *
 * Codes are issued in batches (10) when a user enables MFA; regenerating invalidates the prior
 * batch. Only the keyed HMAC ({@see $codeHash}) is stored — never the plaintext — and a code is
 * spent by stamping {@see $usedAt}.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
class RecoveryCode
{
    public string $id = '';
    public string $userId = '';

    /** Keyed HMAC-SHA256 (hex) of the plaintext recovery code; never the code itself. */
    public string $codeHash = '';
    public ?DateTimeImmutable $usedAt = null;
    public DateTimeImmutable $createdAt;
}
