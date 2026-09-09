<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use PDO;
use Polaris\Contract\Dialect;
use Polaris\Schema\FieldType;

use function array_values;
use function explode;
use function in_array;
use function ksort;
use function preg_match;
use function sprintf;
use function str_starts_with;
use function strtolower;
use function trim;

/**
 * Reads the live schema of the Polaris tables (columns, nullability, primary key, indexes) into
 * the same vocabulary the schema definitions use, so {@see SchemaDiff} can compare them.
 */
final class SchemaInspector
{
    public function __construct(private readonly PDO $pdo, private readonly Dialect $dialect)
    {
    }

    /**
     * @return array{columns: array<string, array{type: ?FieldType, length: ?int, nullable: bool, raw: string}>, primary: list<string>, indexes: list<array{columns: list<string>, unique: bool}>}|null null when the table does not exist
     */
    public function table(string $table): ?array
    {
        return match ($this->dialect) {
            Dialect::Sqlite, Dialect::Memory => $this->sqlite($table),
            Dialect::Postgres => $this->postgres($table),
            Dialect::Mysql => $this->mysql($table),
            Dialect::Mssql => null,
        };
    }

    /**
     * @return array{columns: array<string, array{type: ?FieldType, length: ?int, nullable: bool, raw: string}>, primary: list<string>, indexes: list<array{columns: list<string>, unique: bool}>}|null
     */
    private function sqlite(string $table): ?array
    {
        $columns = [];
        $primary = [];
        foreach ($this->pdo->query(sprintf('PRAGMA table_info("%s")', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $columns[(string) $row['name']] = ['nullable' => (int) $row['notnull'] === 0, 'raw' => (string) $row['type'], ...self::type((string) $row['type'], null)];
            if ((int) $row['pk'] > 0) {
                $primary[(int) $row['pk']] = (string) $row['name'];
            }
        }
        if ($columns === []) {
            return null;
        }
        ksort($primary);
        $indexes = [];
        foreach ($this->pdo->query(sprintf('PRAGMA index_list("%s")', $table))->fetchAll(PDO::FETCH_ASSOC) as $index) {
            if (($index['origin'] ?? 'c') === 'pk') {
                continue;
            }
            $cols = [];
            foreach ($this->pdo->query(sprintf('PRAGMA index_info("%s")', $index['name']))->fetchAll(PDO::FETCH_ASSOC) as $col) {
                $cols[(int) $col['seqno']] = (string) $col['name'];
            }
            ksort($cols);
            $indexes[] = ['columns' => array_values($cols), 'unique' => (int) $index['unique'] === 1];
        }

        return ['columns' => $columns, 'primary' => array_values($primary), 'indexes' => $indexes];
    }

    /**
     * @return array{columns: array<string, array{type: ?FieldType, length: ?int, nullable: bool, raw: string}>, primary: list<string>, indexes: list<array{columns: list<string>, unique: bool}>}|null
     */
    private function postgres(string $table): ?array
    {
        $statement = $this->pdo->prepare('SELECT column_name, data_type, character_maximum_length, is_nullable FROM information_schema.columns WHERE table_name = ? AND table_schema = current_schema() ORDER BY ordinal_position');
        $statement->execute([$table]);
        $columns = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $columns[(string) $row['column_name']] = ['nullable' => $row['is_nullable'] === 'YES', 'raw' => (string) $row['data_type'], ...self::type((string) $row['data_type'], $row['character_maximum_length'] === null ? null : (int) $row['character_maximum_length'])];
        }
        if ($columns === []) {
            return null;
        }
        $statement = $this->pdo->prepare('SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) WHERE i.indrelid = ?::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)');
        $statement->execute([$table]);
        $primary = array_map(static fn(mixed $c): string => (string) $c, $statement->fetchAll(PDO::FETCH_COLUMN));
        $statement = $this->pdo->prepare('SELECT indexdef FROM pg_indexes WHERE tablename = ? AND schemaname = current_schema()');
        $statement->execute([$table]);
        $indexes = [];
        foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $definition) {
            $definition = (string) $definition;
            if (preg_match('/\(([^)]+)\)/', $definition, $match) !== 1) {
                continue;
            }
            $cols = array_map(static fn(string $c): string => trim($c, ' "'), explode(',', $match[1]));
            if ($cols === $primary) {
                continue;
            }
            $indexes[] = ['columns' => $cols, 'unique' => str_starts_with($definition, 'CREATE UNIQUE')];
        }

        return ['columns' => $columns, 'primary' => $primary, 'indexes' => $indexes];
    }

    /**
     * @return array{columns: array<string, array{type: ?FieldType, length: ?int, nullable: bool, raw: string}>, primary: list<string>, indexes: list<array{columns: list<string>, unique: bool}>}|null
     */
    private function mysql(string $table): ?array
    {
        $statement = $this->pdo->prepare('SELECT column_name, column_type, character_maximum_length, is_nullable FROM information_schema.columns WHERE table_name = ? AND table_schema = DATABASE() ORDER BY ordinal_position');
        $statement->execute([$table]);
        $columns = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $columns[(string) $row['column_name']] = ['nullable' => $row['is_nullable'] === 'YES', 'raw' => (string) $row['column_type'], ...self::type((string) $row['column_type'], $row['character_maximum_length'] === null ? null : (int) $row['character_maximum_length'])];
        }
        if ($columns === []) {
            return null;
        }
        $byName = [];
        $primary = [];
        foreach ($this->pdo->query(sprintf('SHOW INDEX FROM `%s`', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
            if ($row['Key_name'] === 'PRIMARY') {
                $primary[(int) $row['Seq_in_index']] = (string) $row['Column_name'];
                continue;
            }
            $byName[(string) $row['Key_name']]['columns'][(int) $row['Seq_in_index']] = (string) $row['Column_name'];
            $byName[(string) $row['Key_name']]['unique'] = (int) $row['Non_unique'] === 0;
        }
        ksort($primary);
        $indexes = [];
        foreach ($byName as $index) {
            ksort($index['columns']);
            $indexes[] = ['columns' => array_values($index['columns']), 'unique' => $index['unique']];
        }

        return ['columns' => $columns, 'primary' => array_values($primary), 'indexes' => $indexes];
    }

    /**
     * @return array{type: ?FieldType, length: ?int}
     */
    private static function type(string $raw, ?int $length): array
    {
        $lower = strtolower(trim($raw));
        if (preg_match('/^(?:character varying|varchar)\s*\((\d+)\)$/', $lower, $m) === 1) {
            return ['type' => FieldType::String, 'length' => (int) $m[1]];
        }
        if (in_array($lower, ['character varying', 'varchar'], true)) {
            return ['type' => FieldType::String, 'length' => $length];
        }
        if (str_starts_with($lower, 'tinyint(1)') || in_array($lower, ['boolean', 'bool'], true)) {
            return ['type' => FieldType::Bool, 'length' => null];
        }
        if (preg_match('/^(?:int|integer|bigint|smallint)/', $lower) === 1) {
            return ['type' => FieldType::Int, 'length' => null];
        }
        if (str_starts_with($lower, 'timestamp') || $lower === 'datetime') {
            return ['type' => FieldType::DateTime, 'length' => null];
        }
        if (in_array($lower, ['json', 'jsonb'], true)) {
            return ['type' => FieldType::Json, 'length' => null];
        }
        if ($lower === 'text' || str_starts_with($lower, 'longtext') || str_starts_with($lower, 'mediumtext')) {
            return ['type' => FieldType::Text, 'length' => null];
        }

        return ['type' => null, 'length' => $length];
    }
}
