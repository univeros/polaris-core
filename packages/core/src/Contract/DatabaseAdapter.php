<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * Row-level access to one database. Rows are `column => value` arrays.
 *
 * Criteria are `column => value` where a scalar means equality, a list means IN, null means
 * IS NULL, and a {@see Condition} means its comparison; entries are ANDed. Values crossing
 * this boundary are PHP scalars, null, and DateTimeImmutable; adapters serialise them for
 * their driver and return raw driver values, which the repository hydrates by schema type.
 * Update data may carry an {@see Increment}.
 */
interface DatabaseAdapter
{
    /**
     * @param array<string, mixed> $criteria
     * @return array<string, mixed>|null
     */
    public function findOne(string $table, array $criteria): ?array;

    /**
     * @param array<string, mixed> $criteria
     * @param array<string, 'asc'|'desc'>|null $orderBy
     * @return list<array<string, mixed>>
     */
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array;

    /**
     * @param array<string, mixed> $row
     */
    public function insert(string $table, array $row): void;

    /**
     * @param array<string, mixed> $criteria
     * @param array<string, mixed> $data
     * @return int affected rows
     */
    public function update(string $table, array $criteria, array $data): int;

    /**
     * @param array<string, mixed> $criteria
     * @return int affected rows
     */
    public function delete(string $table, array $criteria): int;

    /**
     * @param array<string, mixed> $criteria
     */
    public function count(string $table, array $criteria): int;

    /**
     * Runs `$fn` inside a transaction (a savepoint when nested), committing on return and
     * rolling back when it throws.
     *
     * @template R
     * @param callable(): R $fn
     * @return R
     */
    public function transaction(callable $fn): mixed;

    public function dialect(): Dialect;
}
