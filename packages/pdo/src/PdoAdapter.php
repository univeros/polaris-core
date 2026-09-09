<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use DateTimeInterface;
use LogicException;
use Override;
use PDO;
use PDOStatement;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Contract\Increment;
use Throwable;

use function array_fill;
use function array_keys;
use function array_values;
use function count;
use function implode;
use function is_bool;
use function is_int;
use function sprintf;
use function strtolower;

/**
 * {@see DatabaseAdapter} over PDO for PostgreSQL, MySQL and SQLite. Prepared statements only;
 * nested transactions use savepoints.
 */
final class PdoAdapter implements DatabaseAdapter
{
    private readonly Dialect $dialect;
    private int $depth = 0;

    public function __construct(private readonly PDO $pdo, ?Dialect $dialect = null)
    {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->dialect = $dialect ?? self::detect($pdo);
    }

    #[Override]
    public function findOne(string $table, array $criteria): ?array
    {
        return $this->findMany($table, $criteria, null, 1)[0] ?? null;
    }

    #[Override]
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array
    {
        [$where, $params] = $this->where($criteria);
        $sql = sprintf('SELECT * FROM %s%s', $this->quote($table), $where);
        if ($orderBy !== null && $orderBy !== []) {
            $order = [];
            foreach ($orderBy as $column => $direction) {
                $order[] = $this->quote($column) . (strtolower($direction) === 'desc' ? ' DESC' : ' ASC');
            }
            $sql .= ' ORDER BY ' . implode(', ', $order);
        }
        if ($limit !== null) {
            $sql .= ' LIMIT ' . $limit;
        }
        if ($offset !== null) {
            $sql .= ($limit === null ? ' LIMIT -1' : '') . ' OFFSET ' . $offset;
        }

        /** @var list<array<string, mixed>> $rows */
        $rows = $this->run($sql, $params)->fetchAll(PDO::FETCH_ASSOC);

        return $rows;
    }

    #[Override]
    public function insert(string $table, array $row): void
    {
        $columns = array_keys($row);
        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $this->quote($table),
            implode(', ', array_map($this->quote(...), $columns)),
            implode(', ', array_fill(0, count($columns), '?')),
        );
        $this->run($sql, array_values($row));
    }

    #[Override]
    public function update(string $table, array $criteria, array $data): int
    {
        $set = [];
        $params = [];
        foreach ($data as $column => $value) {
            if ($value instanceof Increment) {
                $set[] = sprintf('%1$s = %1$s + %2$d', $this->quote($column), $value->by);
            } else {
                $set[] = $this->quote($column) . ' = ?';
                $params[] = $value;
            }
        }
        [$where, $whereParams] = $this->where($criteria);

        return $this->run(sprintf('UPDATE %s SET %s%s', $this->quote($table), implode(', ', $set), $where), [...$params, ...$whereParams])->rowCount();
    }

    #[Override]
    public function delete(string $table, array $criteria): int
    {
        [$where, $params] = $this->where($criteria);

        return $this->run(sprintf('DELETE FROM %s%s', $this->quote($table), $where), $params)->rowCount();
    }

    #[Override]
    public function count(string $table, array $criteria): int
    {
        [$where, $params] = $this->where($criteria);

        return (int) $this->run(sprintf('SELECT COUNT(*) FROM %s%s', $this->quote($table), $where), $params)->fetchColumn();
    }

    #[Override]
    public function transaction(callable $fn): mixed
    {
        $savepoint = 'polaris_sp_' . $this->depth;
        if ($this->depth === 0) {
            $this->pdo->beginTransaction();
        } else {
            $this->pdo->exec('SAVEPOINT ' . $savepoint);
        }
        ++$this->depth;

        try {
            $result = $fn();
            --$this->depth;
            if ($this->depth === 0) {
                $this->pdo->commit();
            } else {
                $this->pdo->exec('RELEASE SAVEPOINT ' . $savepoint);
            }

            return $result;
        } catch (Throwable $exception) {
            --$this->depth;
            if ($this->depth === 0) {
                $this->pdo->rollBack();
            } else {
                $this->pdo->exec('ROLLBACK TO SAVEPOINT ' . $savepoint);
            }
            throw $exception;
        }
    }

    #[Override]
    public function dialect(): Dialect
    {
        return $this->dialect;
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Runs a raw statement, for schema DDL.
     */
    public function exec(string $sql): void
    {
        $this->pdo->exec($sql);
    }

    /**
     * @param array<string, mixed> $criteria
     * @return array{string, list<mixed>} the WHERE clause (with its leading space) and its parameters
     */
    private function where(array $criteria): array
    {
        if ($criteria === []) {
            return ['', []];
        }
        $clauses = [];
        $params = [];
        foreach ($criteria as $column => $value) {
            $quoted = $this->quote($column);
            if ($value instanceof Condition) {
                if ($value->operator === Condition::NOT_NULL) {
                    $clauses[] = $quoted . ' IS NOT NULL';
                } else {
                    $clauses[] = sprintf('%s %s ?', $quoted, $value->operator === Condition::NE ? '<>' : $value->operator);
                    $params[] = $value->value;
                }
            } elseif (is_array($value)) {
                if ($value === []) {
                    $clauses[] = '1 = 0';
                } else {
                    $clauses[] = sprintf('%s IN (%s)', $quoted, implode(', ', array_fill(0, count($value), '?')));
                    $params = [...$params, ...array_values($value)];
                }
            } elseif ($value === null) {
                $clauses[] = $quoted . ' IS NULL';
            } else {
                $clauses[] = $quoted . ' = ?';
                $params[] = $value;
            }
        }

        return [' WHERE ' . implode(' AND ', $clauses), $params];
    }

    /**
     * @param list<mixed> $params
     */
    private function run(string $sql, array $params): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        foreach ($params as $index => $value) {
            $statement->bindValue($index + 1, ...self::bind($value));
        }
        $statement->execute();

        return $statement;
    }

    /**
     * @return array{mixed, int} value and PDO parameter type
     */
    private static function bind(mixed $value): array
    {
        return match (true) {
            $value === null => [null, PDO::PARAM_NULL],
            is_bool($value) => [$value, PDO::PARAM_BOOL],
            is_int($value) => [$value, PDO::PARAM_INT],
            $value instanceof DateTimeInterface => [$value->format('Y-m-d H:i:s'), PDO::PARAM_STR],
            default => [$value, PDO::PARAM_STR],
        };
    }

    private function quote(string $identifier): string
    {
        return $this->dialect === Dialect::Mysql ? "`$identifier`" : "\"$identifier\"";
    }

    private static function detect(PDO $pdo): Dialect
    {
        $driver = (string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        return match ($driver) {
            'pgsql' => Dialect::Postgres,
            'mysql' => Dialect::Mysql,
            'sqlite' => Dialect::Sqlite,
            'sqlsrv', 'dblib' => Dialect::Mssql,
            default => throw new LogicException(sprintf('Unsupported PDO driver "%s".', $driver)),
        };
    }
}
