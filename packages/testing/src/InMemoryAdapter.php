<?php

declare(strict_types=1);

namespace Polaris\Testing;

use DateTimeInterface;
use Override;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Contract\Increment;
use Throwable;

use function array_key_exists;
use function array_slice;
use function count;
use function in_array;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function strtolower;
use function usort;

/**
 * A {@see DatabaseAdapter} over PHP arrays, with the full criteria semantics (equality, IN,
 * IS NULL, {@see Condition}), ordering, limits, {@see Increment}, and transactions that roll
 * back on exceptions. Values are kept as given.
 */
final class InMemoryAdapter implements DatabaseAdapter
{
    /** @var array<string, list<array<string, mixed>>> */
    private array $tables = [];

    #[Override]
    public function findOne(string $table, array $criteria): ?array
    {
        return $this->findMany($table, $criteria, null, 1)[0] ?? null;
    }

    #[Override]
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array
    {
        $rows = [];
        foreach ($this->tables[$table] ?? [] as $row) {
            if (self::matches($row, $criteria)) {
                $rows[] = $row;
            }
        }
        if ($orderBy !== null && $orderBy !== []) {
            usort($rows, static function (array $a, array $b) use ($orderBy): int {
                foreach ($orderBy as $column => $direction) {
                    $order = self::compare($a[$column] ?? null, $b[$column] ?? null);
                    if ($order !== 0) {
                        return strtolower($direction) === 'desc' ? -$order : $order;
                    }
                }

                return 0;
            });
        }

        return array_slice($rows, $offset ?? 0, $limit);
    }

    #[Override]
    public function insert(string $table, array $row): void
    {
        $this->tables[$table][] = $row;
    }

    #[Override]
    public function update(string $table, array $criteria, array $data): int
    {
        $affected = 0;
        foreach ($this->tables[$table] ?? [] as $index => $row) {
            if (!self::matches($row, $criteria)) {
                continue;
            }
            foreach ($data as $column => $value) {
                $row[$column] = $value instanceof Increment ? (int) ($row[$column] ?? 0) + $value->by : $value;
            }
            $this->tables[$table][$index] = $row;
            ++$affected;
        }

        return $affected;
    }

    #[Override]
    public function delete(string $table, array $criteria): int
    {
        $kept = [];
        $affected = 0;
        foreach ($this->tables[$table] ?? [] as $row) {
            if (self::matches($row, $criteria)) {
                ++$affected;
            } else {
                $kept[] = $row;
            }
        }
        $this->tables[$table] = $kept;

        return $affected;
    }

    #[Override]
    public function count(string $table, array $criteria): int
    {
        return count($this->findMany($table, $criteria));
    }

    #[Override]
    public function transaction(callable $fn): mixed
    {
        $snapshot = $this->tables;
        try {
            return $fn();
        } catch (Throwable $exception) {
            $this->tables = $snapshot;
            throw $exception;
        }
    }

    #[Override]
    public function dialect(): Dialect
    {
        return Dialect::Memory;
    }

    /**
     * Every row of a table, for assertions.
     *
     * @return list<array<string, mixed>>
     */
    public function rows(string $table): array
    {
        return $this->tables[$table] ?? [];
    }

    /**
     * @param array<string, mixed> $row
     * @param array<string, mixed> $criteria
     */
    private static function matches(array $row, array $criteria): bool
    {
        foreach ($criteria as $column => $expected) {
            $actual = array_key_exists($column, $row) ? $row[$column] : null;
            if ($expected instanceof Condition) {
                if (!self::satisfies($actual, $expected)) {
                    return false;
                }
            } elseif (is_array($expected)) {
                if ($actual === null || !in_array(self::normalise($actual), self::normaliseAll($expected), true)) {
                    return false;
                }
            } elseif ($expected === null) {
                if ($actual !== null) {
                    return false;
                }
            } elseif ($actual === null || self::normalise($actual) !== self::normalise($expected)) {
                return false;
            }
        }

        return true;
    }

    private static function satisfies(mixed $actual, Condition $condition): bool
    {
        if ($condition->operator === Condition::NOT_NULL) {
            return $actual !== null;
        }
        if ($actual === null || $condition->value === null) {
            return false;
        }
        $order = self::compare($actual, $condition->value);

        return match ($condition->operator) {
            Condition::LT => $order < 0,
            Condition::LTE => $order <= 0,
            Condition::GT => $order > 0,
            Condition::GTE => $order >= 0,
            Condition::NE => $order !== 0,
            default => false,
        };
    }

    private static function compare(mixed $a, mixed $b): int
    {
        if ($a === null || $b === null) {
            return $a === null ? ($b === null ? 0 : -1) : 1;
        }

        return self::normalise($a) <=> self::normalise($b);
    }

    private static function normalise(mixed $value): mixed
    {
        if ($value instanceof DateTimeInterface) {
            return $value->format('Y-m-d H:i:s.u');
        }
        if (is_bool($value)) {
            return $value ? 1 : 0;
        }
        if (is_string($value) || is_int($value)) {
            return (string) $value;
        }

        return $value;
    }

    /**
     * @param list<mixed> $values
     * @return list<mixed>
     */
    private static function normaliseAll(array $values): array
    {
        $out = [];
        foreach ($values as $value) {
            $out[] = self::normalise($value);
        }

        return $out;
    }
}
