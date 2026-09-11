<?php

declare(strict_types=1);

namespace Polaris\Sso;

use RuntimeException;

/**
 * Why a sign-in could not proceed; `$reason` is the problem name (`assertion_invalid`, `user_unknown`,
 * ...) and `$detail` what the audit trail records, never sent to the caller when generic.
 */
final class SsoException extends RuntimeException
{
    public const string PROVIDER_NOT_FOUND = 'provider_not_found';
    public const string PROVIDER_DISABLED = 'provider_disabled';
    public const string INVALID_INPUT = 'invalid_input';
    public const string ASSERTION_INVALID = 'assertion_invalid';
    public const string USER_UNKNOWN = 'user_unknown';
    public const string ACCOUNT_DISABLED = 'account_disabled';
    public const string MEMBERSHIP_SUSPENDED = 'membership_suspended';
    public const string CODE_INVALID = 'code_invalid';

    public function __construct(public readonly string $reason, public readonly string $detail)
    {
        parent::__construct($detail);
    }
}
