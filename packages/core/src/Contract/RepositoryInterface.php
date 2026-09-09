<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * Read access to one model's storage. Writes go through {@see UnitOfWorkInterface}.
 *
 * `$criteria` is `column => scalar | list<scalar> | null`, meaning equality, IN, and IS NULL.
 *
 * @template T of object
 */
interface RepositoryInterface
{
    /**
     * @return T|null
     */
    public function find(int|string $id): ?object;

    /**
     * @param array<string, mixed> $criteria
     * @return T|null
     */
    public function findOneBy(array $criteria): ?object;

    /**
     * @param array<string, mixed> $criteria
     * @return iterable<T>
     */
    public function findBy(array $criteria): iterable;

    /**
     * @return iterable<T>
     */
    public function findAll(): iterable;
}
