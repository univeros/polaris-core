<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Reading and writing the driver's raw values: JSON columns as strings, datetimes, nullable strings.
 */
final class Rows
{
    private function __construct()
    {
    }

    public static function json(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @return array<mixed>|null
     */
    public static function array(mixed $value): ?array
    {
        $decoded = is_string($value) ? json_decode($value, true) : $value;

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * @return list<string>
     */
    public static function strings(mixed $value): array
    {
        return array_values(array_filter(self::array($value) ?? [], is_string(...)));
    }

    public static function nullable(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    public static function int(mixed $value): ?int
    {
        return $value === null || $value === '' ? null : (int) $value;
    }

    public static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
