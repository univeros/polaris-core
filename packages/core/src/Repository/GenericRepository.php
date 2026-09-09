<?php

declare(strict_types=1);

namespace Polaris\Repository;

use LogicException;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\RepositoryInterface;
use Polaris\Schema\Model;

use function count;
use function sprintf;

/**
 * Reads one model's rows through a {@see DatabaseAdapter} and hydrates them by the schema.
 * Criteria use property names. An object already in the identity map is returned as is.
 *
 * @template T of object
 * @implements RepositoryInterface<T>
 */
class GenericRepository implements RepositoryInterface
{
    public function __construct(
        protected readonly DatabaseAdapter $database,
        protected readonly Model $model,
        protected readonly IdentityMap $identities,
    ) {
    }

    /**
     * @return T|null
     */
    public function find(int|string $id): ?object
    {
        $key = $this->model->primaryKey();
        if (count($key) !== 1) {
            throw new LogicException(sprintf('%s has a composite key; use findOneBy().', $this->model->class));
        }

        return $this->findOneBy([$key[0]->property => $id]);
    }

    /**
     * @param array<string, mixed> $criteria
     * @return T|null
     */
    public function findOneBy(array $criteria): ?object
    {
        $row = $this->database->findOne($this->model->table, RowMapper::criteria($this->model, $criteria));

        return $row === null ? null : $this->load($row);
    }

    /**
     * @param array<string, mixed> $criteria
     * @return list<T>
     */
    public function findBy(array $criteria): iterable
    {
        $objects = [];
        foreach ($this->database->findMany($this->model->table, RowMapper::criteria($this->model, $criteria)) as $row) {
            $objects[] = $this->load($row);
        }

        return $objects;
    }

    /**
     * @return list<T>
     */
    public function findAll(): iterable
    {
        return $this->findBy([]);
    }

    /**
     * @param array<string, mixed> $row
     * @return T
     */
    protected function load(array $row): object
    {
        $key = IdentityMap::keyOf(RowMapper::primaryKeyOfRow($this->model, $row));
        $known = $this->identities->get($this->model->class, $key);
        if ($known !== null) {
            /** @var T $known */
            return $known;
        }

        $object = RowMapper::hydrate($this->model, $row);
        $this->identities->remember($object, $key, RowMapper::toRow($this->model, $object));

        /** @var T $object */
        return $object;
    }
}
