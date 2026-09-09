<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A registered multi-factor authenticator for a user (table `auth_mfa_factors`).
 *
 * A factor only satisfies MFA once {@see $confirmedAt} is set — enrollment creates an
 * unconfirmed factor that a verify step confirms. TOTP factors keep their shared secret
 * {@see $secretEncrypted} **encrypted** (reversible, via the framework `Encrypter`), since it
 * must be recoverable to verify codes; SMS/email factors carry a destination instead and verify
 * against a per-challenge {@see OtpChallenge}.
 *
 * See `docs/auth/data-model.md` and `docs/auth/mfa-otp.md`.
 */
class MfaFactor
{
    /** `type` values. */
    public const string TYPE_TOTP = 'totp';
    public const string TYPE_SMS = 'sms';
    public const string TYPE_EMAIL = 'email';
    public string $id = '';
    public string $userId = '';

    /** One of `totp`, `sms`, `email`. */
    public string $type = '';
    public ?string $label = null;

    /** TOTP shared secret, encrypted (never stored in plaintext); null for sms/email factors. */
    public ?string $secretEncrypted = null;
    public ?string $phoneE164 = null;
    public ?string $email = null;
    public bool $isDefault = false;
    public ?DateTimeImmutable $confirmedAt = null;
    public ?DateTimeImmutable $lastUsedAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;
}
