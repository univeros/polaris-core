<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Polaris\Contract\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\PasswordReset;

/**
 * Cycle-backed repository for {@see PasswordReset}, pinned to the entity. Lookups by
 * `tokenHash` drive password-reset confirmation.
 *
 * @extends CycleRepository<PasswordReset>
 * @implements RepositoryInterface<PasswordReset>
 */
final class PasswordResetRepository extends CycleRepository implements RepositoryInterface
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(PasswordReset::class, $orm, $unitOfWork);
    }
}
