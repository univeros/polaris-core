<?php

declare(strict_types=1);

namespace Polaris\Repository;

use function implode;
use function spl_object_id;

/**
 * The objects loaded or written in this unit of work, keyed by class and primary key, with the
 * row each one was last read from or written as. Lets `persist()` tell insert from update and
 * write only what changed, and makes two loads of one row yield one instance.
 */
final class IdentityMap
{
    /** @var array<class-string, array<string, object>> */
    private array $objects = [];

    /** @var array<int, array<string, mixed>> */
    private array $rows = [];

    /**
     * @param list<mixed> $primaryKey
     */
    public static function keyOf(array $primaryKey): string
    {
        return implode("\0", $primaryKey);
    }

    public function get(string $class, string $key): ?object
    {
        return $this->objects[$class][$key] ?? null;
    }

    /**
     * @param array<string, mixed> $row
     */
    public function remember(object $object, string $key, array $row): void
    {
        $this->objects[$object::class][$key] = $object;
        $this->rows[spl_object_id($object)] = $row;
    }

    /**
     * @return array<string, mixed>|null the row this object was last read from or written as; null when unknown
     */
    public function rowOf(object $object): ?array
    {
        return $this->rows[spl_object_id($object)] ?? null;
    }

    public function forget(object $object, string $key): void
    {
        unset($this->objects[$object::class][$key], $this->rows[spl_object_id($object)]);
    }

    public function clear(): void
    {
        $this->objects = [];
        $this->rows = [];
    }
}
