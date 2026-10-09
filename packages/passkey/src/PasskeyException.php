<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use RuntimeException;

/**
 * Why a passkey step could not proceed; `$reason` is the problem name (`credential_invalid`,
 * `origin_mismatch`, ...), `$detail` what the caller may say.
 */
final class PasskeyException extends RuntimeException
{
    public const string INVALID_INPUT = 'invalid_input';
    public const string ORIGIN_MISMATCH = 'origin_mismatch';
    public const string CHALLENGE_INVALID = 'challenge_invalid';
    public const string CREDENTIAL_INVALID = 'credential_invalid';
    public const string ACCOUNT_DISABLED = 'account_disabled';
    public const string EMAIL_UNVERIFIED = 'email_unverified';
    public const string USER_VERIFICATION_REQUIRED = 'user_verification_required';
    public const string NOT_FOUND = 'not_found';
    public const string LAST_FACTOR = 'last_factor';

    public function __construct(public readonly string $reason, public readonly string $detail)
    {
        parent::__construct($detail);
    }
}
