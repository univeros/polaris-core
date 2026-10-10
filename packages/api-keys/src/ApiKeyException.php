<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use RuntimeException;

/**
 * A refused API-key operation: the reason names the problem type (`api-keys/<reason>`), the detail is
 * what the client may read.
 */
final class ApiKeyException extends RuntimeException
{
    public const string NOT_FOUND = 'not_found';
    public const string INVALID_INPUT = 'invalid_input';
    public const string FORBIDDEN = 'forbidden';
    public const string TOO_MANY = 'too_many';
    public const string PERMISSION_NOT_HELD = 'permission_not_held';

    public function __construct(public readonly string $reason, public readonly string $detail)
    {
        parent::__construct($detail);
    }
}
