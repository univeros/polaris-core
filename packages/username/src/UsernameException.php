<?php

declare(strict_types=1);

namespace Polaris\Username;

use RuntimeException;

/**
 * Why a username was refused: `invalid` (with the rule violations) or `taken`.
 */
final class UsernameException extends RuntimeException
{
    public const string INVALID = 'invalid';
    public const string TAKEN = 'taken';

    /**
     * @param list<string> $errors
     */
    public function __construct(public readonly string $reason, public readonly array $errors = [])
    {
        parent::__construct($reason === self::TAKEN ? 'The username is taken.' : 'The username is not valid.');
    }
}
