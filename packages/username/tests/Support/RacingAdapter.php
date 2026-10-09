<?php

declare(strict_types=1);

namespace Polaris\Username\Tests\Support;

use DateTimeImmutable;
use Override;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Username\Schema;

/**
 * Lets another user take `grace` right before the first username insert, after the lookup.
 */
final class RacingAdapter implements DatabaseAdapter
{
    private bool $raced = false;

    public function __construct(private readonly DatabaseAdapter $inner)
    {
    }

    #[Override]
    public function findOne(string $table, array $criteria): ?array
    {
        return $this->inner->findOne($table, $criteria);
    }

    #[Override]
    public function findMany(string $table, array $criteria, ?array $orderBy = null, ?int $limit = null, ?int $offset = null): array
    {
        return $this->inner->findMany($table, $criteria, $orderBy, $limit, $offset);
    }

    #[Override]
    public function insert(string $table, array $row): void
    {
        if ($table === Schema::USERNAMES && !$this->raced) {
            $this->raced = true;
            $this->inner->insert($table, ['user_id' => 'u1', 'username' => 'grace', 'display_username' => 'grace', 'created_at' => new DateTimeImmutable(), 'updated_at' => new DateTimeImmutable()]);
        }
        $this->inner->insert($table, $row);
    }

    #[Override]
    public function update(string $table, array $criteria, array $data): int
    {
        return $this->inner->update($table, $criteria, $data);
    }

    #[Override]
    public function delete(string $table, array $criteria): int
    {
        return $this->inner->delete($table, $criteria);
    }

    #[Override]
    public function count(string $table, array $criteria): int
    {
        return $this->inner->count($table, $criteria);
    }

    #[Override]
    public function transaction(callable $fn): mixed
    {
        return $this->inner->transaction($fn);
    }

    #[Override]
    public function dialect(): Dialect
    {
        return $this->inner->dialect();
    }
}
