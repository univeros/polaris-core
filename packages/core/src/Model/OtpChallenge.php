<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A transient one-time-password challenge (table `auth_otp_challenges`): the SMS/email code sent
 * for a login MFA step, enrollment, step-up, or an OTP-style email-verify / password-reset.
 *
 * The numeric code is never stored — only its keyed HMAC ({@see $codeHash}); for `totp` factors
 * the code is verified live against the factor secret, so {@see $codeHash} is null. A challenge is
 * single-use ({@see $consumedAt}), time-boxed ({@see $expiresAt}), and brute-force-bounded
 * ({@see $attempts} / {@see $maxAttempts}). The short-lived `mfa_token` returned by login is a
 * signed JWT, not a row here — this row holds the actual code.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
class OtpChallenge
{
    /** `channel` values. */
    public const string CHANNEL_SMS = 'sms';
    public const string CHANNEL_EMAIL = 'email';
    public const string CHANNEL_TOTP = 'totp';

    /** Default number of verify tries before a challenge is exhausted. */
    public const int DEFAULT_MAX_ATTEMPTS = 5;
    public string $id = '';
    public string $userId = '';
    public ?string $factorId = null;

    /** A {@see \Polaris\Mfa\ChallengePurpose} backing value. */
    public string $purpose = '';

    /** One of `sms`, `email`, `totp`. */
    public string $channel = '';

    /** Keyed HMAC-SHA256 (hex) of the numeric code; null for `totp` (verified live). */
    public ?string $codeHash = null;
    public ?string $destination = null;
    public int $attempts = 0;
    public int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS;
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $consumedAt = null;
    public ?string $ip = null;
    public DateTimeImmutable $createdAt;
}
