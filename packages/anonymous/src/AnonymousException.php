<?php

declare(strict_types=1);

namespace Polaris\Anonymous;

use RuntimeException;

/**
 * Why a conversion was refused: the caller is not a guest still waiting (`not_a_guest`), or the token
 * of the account to convert into is not a live session of another, real account (`token_invalid`).
 */
final class AnonymousException extends RuntimeException
{
    public const string NOT_A_GUEST = 'not_a_guest';
    public const string TOKEN_INVALID = 'token_invalid';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason === self::NOT_A_GUEST ? 'Only a guest session can be converted.' : 'The access token is not a live session of another account.');
    }
}
