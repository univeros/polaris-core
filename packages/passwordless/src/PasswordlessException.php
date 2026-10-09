<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use RuntimeException;

/**
 * Why a passwordless step could not proceed; `$reason` is the problem name (`code_invalid`,
 * `token_invalid`, ...), `$errors` the details of an `invalid_input` or a `password_invalid`.
 */
final class PasswordlessException extends RuntimeException
{
    public const string INVALID_INPUT = 'invalid_input';
    public const string REDIRECT_NOT_ALLOWED = 'redirect_not_allowed';
    public const string CODE_INVALID = 'code_invalid';
    public const string TOKEN_INVALID = 'token_invalid';
    public const string ACCOUNT_DISABLED = 'account_disabled';
    public const string PASSWORD_INVALID = 'password_invalid';
    public const string PHONE_TAKEN = 'phone_taken';
    public const string SESSION_REQUIRED = 'session_required';

    /**
     * @param list<string> $errors
     */
    public function __construct(public readonly string $reason, string $message, public readonly array $errors = [])
    {
        parent::__construct($message);
    }

    public static function codeInvalid(): self
    {
        return new self(self::CODE_INVALID, 'The code is wrong, used or expired.');
    }

    public static function tokenInvalid(): self
    {
        return new self(self::TOKEN_INVALID, 'The token is unknown, used or expired.');
    }
}
