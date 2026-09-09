<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use Polaris\Contract\Dialect;
use Polaris\Schema\Field;
use Polaris\Schema\FieldType;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;

use function array_map;
use function implode;
use function in_array;
use function sprintf;

/**
 * Differences between the Polaris schema definitions and a live database.
 */
final class SchemaDiff
{
    public function __construct(private readonly SchemaInspector $inspector, private readonly Dialect $dialect)
    {
    }

    /**
     * @return list<string> one line per difference; empty when the database matches the schema
     */
    public function run(): array
    {
        $differences = [];
        foreach (Schema::all() as $model) {
            $live = $this->inspector->table($model->table);
            if ($live === null) {
                $differences[] = sprintf('%s: table is missing', $model->table);
                continue;
            }
            foreach ($model->fields as $field) {
                $column = $live['columns'][$field->column] ?? null;
                if ($column === null) {
                    $differences[] = sprintf('%s.%s: column is missing', $model->table, $field->column);
                    continue;
                }
                if (!$this->sameType($field, $column['type'], $column['length'])) {
                    $differences[] = sprintf('%s.%s: expected %s, found %s', $model->table, $field->column, self::describe($field), $column['raw']);
                }
                if ($column['nullable'] !== $field->nullable) {
                    $differences[] = sprintf('%s.%s: expected %s, found %s', $model->table, $field->column, $field->nullable ? 'NULL' : 'NOT NULL', $column['nullable'] ? 'NULL' : 'NOT NULL');
                }
            }
            foreach ($live['columns'] as $name => $column) {
                if (!self::hasColumn($model, $name)) {
                    $differences[] = sprintf('%s.%s: extra column (%s)', $model->table, $name, $column['raw']);
                }
            }
            $primary = array_map(static fn(Field $f): string => $f->column, $model->primaryKey());
            if ($live['primary'] !== $primary) {
                $differences[] = sprintf('%s: expected primary key (%s), found (%s)', $model->table, implode(', ', $primary), implode(', ', $live['primary']));
            }
            foreach ($model->indexes as $index) {
                $found = false;
                foreach ($live['indexes'] as $candidate) {
                    if ($candidate['columns'] === $index->columns && $candidate['unique'] === $index->unique) {
                        $found = true;
                    }
                }
                if (!$found) {
                    $differences[] = sprintf('%s: %s index on (%s) is missing', $model->table, $index->unique ? 'unique' : 'plain', implode(', ', $index->columns));
                }
            }
        }

        return $differences;
    }

    private function sameType(Field $field, ?FieldType $live, ?int $length): bool
    {
        if ($live === null) {
            return false;
        }
        if ($field->type === FieldType::String) {
            return $live === FieldType::String && ($length === null || $length === $field->length);
        }
        if ($field->type === FieldType::Bool && in_array($this->dialect, [Dialect::Sqlite, Dialect::Memory], true)) {
            return in_array($live, [FieldType::Bool, FieldType::Int], true);
        }
        if ($field->type === FieldType::Json && in_array($this->dialect, [Dialect::Sqlite, Dialect::Memory], true)) {
            return in_array($live, [FieldType::Json, FieldType::Text], true);
        }

        return $live === $field->type;
    }

    private static function hasColumn(Model $model, string $column): bool
    {
        foreach ($model->fields as $field) {
            if ($field->column === $column) {
                return true;
            }
        }

        return false;
    }

    private static function describe(Field $field): string
    {
        return $field->type === FieldType::String ? sprintf('string(%d)', $field->length ?? 0) : $field->type->value;
    }
}
