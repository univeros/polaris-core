<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Cycle\Database\DatabaseInterface;
use Cycle\Database\Injection\Fragment;
use Cycle\Database\Injection\Parameter;
use Override;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Contract\Increment;

use function array_values;
use function is_array;
use function sprintf;
use function strtolower;

/**
 * Univeros glue (gone in WP7): the Polaris {@see DatabaseAdapter} over the framework's Cycle
 * database, so the Univeros wiring and the Postgres test suite run on the new repositories.
 */
final class CycleDatabaseAdapter implements DatabaseAdapter
{
    public function __construct(private readonly DatabaseInterface $database)
    {
    }

    #[Override]
    public function findOne(string $table, array $criteria): ?array
    {
        $row = $this->database->select()->from($table)->where(self::where($criteria))->limit(1)->fetchAll()[0] ?? null;

        return is_array($row) ? $row : null;
    }

    #[Override]
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array
    {
        $query = $this->database->select()->from($table)->where(self::where($criteria));
        foreach ($orderBy ?? [] as $column => $direction) {
            $query = $query->orderBy($column, strtolower($direction) === 'desc' ? 'DESC' : 'ASC');
        }
        if ($limit !== null) {
            $query = $query->limit($limit);
        }
        if ($offset !== null) {
            $query = $query->offset($offset);
        }

        $rows = [];
        foreach ($query->fetchAll() as $row) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    #[Override]
    public function insert(string $table, array $row): void
    {
        $this->database->insert($table)->values($row)->run();
    }

    #[Override]
    public function update(string $table, array $criteria, array $data): int
    {
        $values = [];
        foreach ($data as $column => $value) {
            $values[$column] = $value instanceof Increment ? new Fragment(sprintf('%s + %d', $column, $value->by)) : $value;
        }

        return $this->database->update($table, $values, self::where($criteria))->run();
    }

    #[Override]
    public function delete(string $table, array $criteria): int
    {
        return $this->database->delete($table, self::where($criteria))->run();
    }

    #[Override]
    public function count(string $table, array $criteria): int
    {
        return $this->database->select()->from($table)->where(self::where($criteria))->count();
    }

    #[Override]
    public function transaction(callable $fn): mixed
    {
        return $this->database->transaction(static fn(): mixed => $fn());
    }

    #[Override]
    public function dialect(): Dialect
    {
        return match (strtolower($this->database->getDriver()->getType())) {
            'postgres', 'postgresql', 'pgsql' => Dialect::Postgres,
            'mysql' => Dialect::Mysql,
            'sqlite' => Dialect::Sqlite,
            'sqlserver', 'mssql' => Dialect::Mssql,
            default => Dialect::Sqlite,
        };
    }

    /**
     * @param array<string, mixed> $criteria
     * @return array<string, mixed> a Cycle where-array
     */
    private static function where(array $criteria): array
    {
        $where = [];
        foreach ($criteria as $column => $value) {
            $where[$column] = match (true) {
                $value instanceof Condition => $value->operator === Condition::NOT_NULL
                    ? ['!=' => null]
                    : [$value->operator => $value->value],
                is_array($value) => ['in' => new Parameter(array_values($value))],
                default => $value,
            };
        }

        return $where;
    }
}
