<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Polaris\Contract\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\RefreshToken;

/**
 * Cycle-backed repository for {@see RefreshToken}, pinned to the entity. Lookups by
 * `tokenHash` (refresh exchange) and `familyId` (family revocation) drive the rotation
 * and reuse-detection flow in {@see \Polaris\Token\TokenService}.
 *
 * @extends CycleRepository<RefreshToken>
 * @implements RepositoryInterface<RefreshToken>
 */
final class RefreshTokenRepository extends CycleRepository implements RepositoryInterface
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(RefreshToken::class, $orm, $unitOfWork);
    }
}
