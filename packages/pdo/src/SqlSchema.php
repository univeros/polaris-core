<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use InvalidArgumentException;
use Polaris\Contract\Dialect;
use Polaris\Schema\Field;
use Polaris\Schema\FieldType;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;

use function array_map;
use function count;
use function implode;
use function in_array;
use function is_bool;
use function is_string;
use function sprintf;
use function str_replace;

/**
 * DDL for the Polaris schema, per dialect. Tables are emitted so that a referenced table always
 * precedes the tables that reference it.
 */
final class SqlSchema
{
    /**
     * @return list<string> CREATE TABLE and CREATE INDEX statements for every model
     */
    public static function createAll(Dialect $dialect): array
    {
        $statements = [];
        foreach (self::ordered() as $model) {
            $statements = [...$statements, ...self::create($model, $dialect)];
        }

        return $statements;
    }

    /**
     * @return list<string> DROP TABLE statements, dependants first
     */
    public static function dropAll(Dialect $dialect): array
    {
        $statements = [];
        foreach (array_reverse(self::ordered()) as $model) {
            $statements[] = sprintf('DROP TABLE IF EXISTS %s', self::quote($model->table, $dialect));
        }

        return $statements;
    }

    /**
     * @return list<string>
     */
    public static function create(Model $model, Dialect $dialect): array
    {
        $lines = [];
        foreach ($model->fields as $field) {
            $lines[] = sprintf('    %s %s', self::quote($field->column, $dialect), self::columnDefinition($field, $dialect));
        }
        $primary = array_map(static fn(Field $f): string => self::quote($f->column, $dialect), $model->primaryKey());
        if ($primary !== []) {
            $lines[] = sprintf('    PRIMARY KEY (%s)', implode(', ', $primary));
        }
        foreach ($model->references as $reference) {
            $lines[] = sprintf(
                '    FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s ON UPDATE %s',
                implode(', ', array_map(static fn(string $c): string => self::quote($c, $dialect), $reference->columns)),
                self::quote($reference->referencedTable, $dialect),
                implode(', ', array_map(static fn(string $c): string => self::quote($c, $dialect), $reference->referencedColumns)),
                $reference->onDelete,
                $reference->onUpdate,
            );
        }

        $statements = [sprintf("CREATE TABLE %s (\n%s\n)", self::quote($model->table, $dialect), implode(",\n", $lines))];
        foreach ($model->indexes as $index) {
            $statements[] = sprintf(
                'CREATE %sINDEX %s ON %s (%s)',
                $index->unique ? 'UNIQUE ' : '',
                self::quote($index->name, $dialect),
                self::quote($model->table, $dialect),
                implode(', ', array_map(static fn(string $c): string => self::quote($c, $dialect), $index->columns)),
            );
        }

        return $statements;
    }

    private static function columnDefinition(Field $field, Dialect $dialect): string
    {
        $sql = self::type($field, $dialect);
        $sql .= $field->nullable ? ' NULL' : ' NOT NULL';
        if ($field->hasDefault && $field->default !== null) {
            $sql .= ' DEFAULT ' . self::literal($field->default, $dialect);
        }

        return $sql;
    }

    private static function type(Field $field, Dialect $dialect): string
    {
        return match ($field->type) {
            FieldType::String => sprintf('VARCHAR(%d)', $field->length ?? 255),
            FieldType::Text => 'TEXT',
            FieldType::Int => 'INTEGER',
            FieldType::Bool => match ($dialect) {
                Dialect::Mysql => 'TINYINT(1)',
                Dialect::Sqlite, Dialect::Memory => 'INTEGER',
                default => 'BOOLEAN',
            },
            FieldType::DateTime => $dialect === Dialect::Postgres ? 'TIMESTAMP' : 'DATETIME',
            FieldType::Json => match ($dialect) {
                Dialect::Postgres => 'JSONB',
                Dialect::Mysql => 'JSON',
                default => 'TEXT',
            },
        };
    }

    private static function literal(mixed $value, Dialect $dialect): string
    {
        if (is_bool($value)) {
            return $dialect === Dialect::Postgres ? ($value ? 'TRUE' : 'FALSE') : ($value ? '1' : '0');
        }
        if (is_string($value)) {
            return "'" . str_replace("'", "''", $value) . "'";
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        throw new InvalidArgumentException('Unsupported default value.');
    }

    private static function quote(string $identifier, Dialect $dialect): string
    {
        return $dialect === Dialect::Mysql ? "`$identifier`" : "\"$identifier\"";
    }

    /**
     * @return list<Model> referenced tables before the tables that reference them
     */
    private static function ordered(): array
    {
        $pending = Schema::all();
        $ordered = [];
        $placed = [];
        while ($pending !== []) {
            $progress = false;
            foreach ($pending as $index => $model) {
                $ready = true;
                foreach ($model->references as $reference) {
                    if ($reference->referencedTable !== $model->table && !in_array($reference->referencedTable, $placed, true)) {
                        $ready = false;
                    }
                }
                if ($ready) {
                    $ordered[] = $model;
                    $placed[] = $model->table;
                    unset($pending[$index]);
                    $progress = true;
                }
            }
            if (!$progress) {
                throw new InvalidArgumentException('Circular foreign keys in the schema: ' . count($pending) . ' tables cannot be ordered.');
            }
        }

        return $ordered;
    }
}
