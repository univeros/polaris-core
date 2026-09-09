<?php

declare(strict_types=1);

namespace Polaris\Repository;

use DateTimeInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Schema\Schema;

use function array_values;
use function spl_object_id;

/**
 * Queues persists and removes; `flush()` writes them in order inside one adapter transaction:
 * an object the identity map has not seen is inserted, a known one is updated with only the
 * columns that changed since it was read or last written, a removed one is deleted by key.
 */
final class UnitOfWork implements UnitOfWorkInterface
{
    /** @var array<int, object> */
    private array $persisted = [];

    /** @var array<int, object> */
    private array $removed = [];

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly IdentityMap $identities,
    ) {
    }

    public function persist(object $entity): void
    {
        $id = spl_object_id($entity);
        unset($this->removed[$id]);
        $this->persisted[$id] = $entity;
    }

    public function remove(object $entity): void
    {
        $id = spl_object_id($entity);
        unset($this->persisted[$id]);
        $this->removed[$id] = $entity;
    }

    public function flush(): void
    {
        if ($this->persisted === [] && $this->removed === []) {
            return;
        }

        $persisted = array_values($this->persisted);
        $removed = array_values($this->removed);
        $this->persisted = [];
        $this->removed = [];

        $this->database->transaction(function () use ($persisted, $removed): void {
            foreach ($persisted as $object) {
                $this->write($object);
            }
            foreach ($removed as $object) {
                $this->delete($object);
            }
        });
    }

    /**
     * Drops the queues and the identity map, so the next read hits the database.
     */
    public function clear(): void
    {
        $this->persisted = [];
        $this->removed = [];
        $this->identities->clear();
    }

    public function identities(): IdentityMap
    {
        return $this->identities;
    }

    private function write(object $object): void
    {
        $model = Schema::for($object::class);
        $row = RowMapper::toRow($model, $object);
        $key = IdentityMap::keyOf(RowMapper::primaryKeyOfRow($model, $row));
        $previous = $this->identities->rowOf($object);

        if ($previous === null) {
            $this->database->insert($model->table, $row);
            $this->identities->remember($object, $key, $row);

            return;
        }

        $changes = [];
        foreach ($row as $column => $value) {
            if (!self::same($previous[$column] ?? null, $value)) {
                $changes[$column] = $value;
            }
        }
        if ($changes !== []) {
            $this->database->update($model->table, RowMapper::primaryKey($model, $object), $changes);
        }
        $this->identities->remember($object, $key, $row);
    }

    private function delete(object $object): void
    {
        $model = Schema::for($object::class);
        $this->database->delete($model->table, RowMapper::primaryKey($model, $object));
        $this->identities->forget($object, IdentityMap::keyOf(RowMapper::primaryKeyOfRow($model, RowMapper::toRow($model, $object))));
    }

    private static function same(mixed $a, mixed $b): bool
    {
        if ($a instanceof DateTimeInterface && $b instanceof DateTimeInterface) {
            return $a->format('Y-m-d H:i:s.u') === $b->format('Y-m-d H:i:s.u');
        }

        return $a === $b;
    }
}
