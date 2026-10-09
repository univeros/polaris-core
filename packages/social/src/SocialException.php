<?php

declare(strict_types=1);

namespace Polaris\Social;

use RuntimeException;

/**
 * Why a social step could not proceed; `$reason` is the problem name, `$detail` what the caller may say.
 */
final class SocialException extends RuntimeException
{
    public const string INVALID_INPUT = 'invalid_input';
    public const string PROVIDER_NOT_FOUND = 'provider_not_found';
    public const string REDIRECT_NOT_ALLOWED = 'redirect_not_allowed';
    public const string STATE_INVALID = 'state_invalid';
    public const string PROVIDER_ERROR = 'provider_error';
    public const string TOKEN_INVALID = 'token_invalid';
    public const string EMAIL_REQUIRED = 'email_required';
    public const string EMAIL_MISMATCH = 'email_mismatch';
    public const string ACCOUNT_EXISTS = 'account_exists';
    public const string ACCOUNT_LINKED = 'account_linked';
    public const string ACCOUNT_DISABLED = 'account_disabled';
    public const string EMAIL_UNVERIFIED = 'email_unverified';
    public const string NOT_LINKED = 'not_linked';
    public const string LAST_CREDENTIAL = 'last_credential';
    public const string CODE_INVALID = 'code_invalid';
    public const string NO_REFRESH = 'no_refresh';

    public function __construct(public readonly string $reason, public readonly string $detail)
    {
        parent::__construct($detail);
    }
}
