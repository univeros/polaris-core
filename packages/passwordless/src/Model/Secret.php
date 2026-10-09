<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Model;

use DateTimeImmutable;

/**
 * A link, code or token waiting to be used (`polaris_passwordless_secret`): only keyed hashes of the
 * identifier and of the secret are stored; `data` is what the verify needs (the email, the redirect
 * URI, the session a one-time token transfers).
 */
final class Secret
{
    public const string MAGIC_LINK = 'magic_link';
    public const string EMAIL_SIGN_IN = 'email_otp:sign-in';
    public const string EMAIL_VERIFY = 'email_otp:verify-email';
    public const string EMAIL_RESET = 'email_otp:reset-password';
    public const string PHONE_SIGN_IN = 'phone:sign-in';
    public const string PHONE_ADD = 'phone:add';
    public const string ONE_TIME_TOKEN = 'one_time_token';

    public string $id = '';
    public string $kind = '';
    public string $identifierHash = '';
    public ?string $userId = null;
    public string $secretHash = '';
    public int $attempts = 0;
    /** @var array<string, mixed> */
    public array $data = [];
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $usedAt = null;
    public DateTimeImmutable $createdAt;
}
