<?php

declare(strict_types=1);

namespace Polaris\Repository;

use DateTimeImmutable;
use DateTimeInterface;
use Polaris\Schema\FieldType;
use Polaris\Schema\Model;

use function array_key_exists;
use function in_array;
use function is_bool;
use function is_string;
use function strtolower;

/**
 * Model object <-> row, by the schema. Rows carry PHP scalars, null, and DateTimeImmutable.
 */
final class RowMapper
{
    /**
     * @return array<string, mixed> column => value
     */
    public static function toRow(Model $model, object $object): array
    {
        $row = [];
        foreach ($model->fields as $field) {
            $row[$field->column] = $object->{$field->property};
        }

        return $row;
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function hydrate(Model $model, array $row): object
    {
        $object = new ($model->class)();
        foreach ($model->fields as $field) {
            if (!array_key_exists($field->column, $row)) {
                continue;
            }
            $object->{$field->property} = self::cast($field->type, $row[$field->column]);
        }

        return $object;
    }

    /**
     * @return array<string, mixed> column => value
     */
    public static function primaryKey(Model $model, object $object): array
    {
        $key = [];
        foreach ($model->primaryKey() as $field) {
            $key[$field->column] = $object->{$field->property};
        }

        return $key;
    }

    /**
     * @param array<string, mixed> $row
     * @return list<mixed>
     */
    public static function primaryKeyOfRow(Model $model, array $row): array
    {
        $key = [];
        foreach ($model->primaryKey() as $field) {
            $key[] = $row[$field->column] ?? null;
        }

        return $key;
    }

    /**
     * Property-keyed criteria (what the domain writes) to column-keyed criteria (what adapters take).
     *
     * @param array<string, mixed> $criteria
     * @return array<string, mixed>
     */
    public static function criteria(Model $model, array $criteria): array
    {
        $mapped = [];
        foreach ($criteria as $property => $value) {
            $mapped[$model->columnOf($property)] = $value;
        }

        return $mapped;
    }

    private static function cast(FieldType $type, mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            FieldType::DateTime => $value instanceof DateTimeInterface
                ? DateTimeImmutable::createFromInterface($value)
                : new DateTimeImmutable((string) $value),
            FieldType::Bool => is_bool($value) ? $value : self::toBool($value),
            FieldType::Int => (int) $value,
            FieldType::String, FieldType::Text, FieldType::Json => (string) $value,
        };
    }

    private static function toBool(mixed $value): bool
    {
        if (is_string($value)) {
            return in_array(strtolower($value), ['1', 't', 'true', 'y', 'yes'], true);
        }

        return (bool) $value;
    }
}
