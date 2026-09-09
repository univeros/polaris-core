<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Persistence\Contracts\UnitOfWorkInterface as AltairUnitOfWork;
use Override;
use Polaris\Contract\UnitOfWorkInterface;

/**
 * Univeros glue (gone in WP7): the framework's Cycle unit of work under the Polaris contract.
 */
final class UnitOfWorkBridge implements UnitOfWorkInterface
{
    public function __construct(private readonly AltairUnitOfWork $unitOfWork)
    {
    }

    #[Override]
    public function persist(object $entity): void
    {
        $this->unitOfWork->persist($entity);
    }

    #[Override]
    public function remove(object $entity): void
    {
        $this->unitOfWork->remove($entity);
    }

    #[Override]
    public function flush(): void
    {
        $this->unitOfWork->flush();
    }
}
