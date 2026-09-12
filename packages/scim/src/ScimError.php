<?php

declare(strict_types=1);

namespace Polaris\Scim;

use RuntimeException;

/**
 * A SCIM error (RFC 7644 §3.12): the status, an optional `scimType`, the detail.
 */
final class ScimError extends RuntimeException
{
    public const string INVALID_FILTER = 'invalidFilter';
    public const string INVALID_VALUE = 'invalidValue';
    public const string INVALID_PATH = 'invalidPath';
    public const string INVALID_SYNTAX = 'invalidSyntax';
    public const string UNIQUENESS = 'uniqueness';
    public const string MUTABILITY = 'mutability';

    public function __construct(public readonly int $status, public readonly string $detail, public readonly ?string $scimType = null)
    {
        parent::__construct($detail);
    }

    public static function notFound(string $what): self
    {
        return new self(404, $what . ' not found.');
    }

    public static function invalid(string $detail, string $type = self::INVALID_VALUE): self
    {
        return new self(400, $detail, $type);
    }

    public static function conflict(string $detail): self
    {
        return new self(409, $detail, self::UNIQUENESS);
    }
}
