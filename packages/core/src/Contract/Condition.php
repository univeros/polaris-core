<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * A non-equality criterion. Use as a criteria value: `['expiresAt' => Condition::lt($now)]`.
 * Comparing against NULL never matches, as in SQL.
 */
final readonly class Condition
{
    public const string LT = '<';
    public const string LTE = '<=';
    public const string GT = '>';
    public const string GTE = '>=';
    public const string NE = '!=';
    public const string NOT_NULL = 'not null';

    private function __construct(public string $operator, public mixed $value)
    {
    }

    public static function lt(mixed $value): self
    {
        return new self(self::LT, $value);
    }

    public static function lte(mixed $value): self
    {
        return new self(self::LTE, $value);
    }

    public static function gt(mixed $value): self
    {
        return new self(self::GT, $value);
    }

    public static function gte(mixed $value): self
    {
        return new self(self::GTE, $value);
    }

    public static function ne(mixed $value): self
    {
        return new self(self::NE, $value);
    }

    public static function notNull(): self
    {
        return new self(self::NOT_NULL, null);
    }
}
