<?php

declare(strict_types=1);

namespace Univeros\Polaris\Persistence;

use Polaris\Contract\RepositoryInterface;
use Altair\Persistence\Contracts\UnitOfWorkInterface;
use Altair\Persistence\Cycle\CycleRepository;
use Cycle\ORM\ORMInterface;
use Univeros\Polaris\Entity\EmailVerification;

/**
 * Cycle-backed repository for {@see EmailVerification}, pinned to the entity. Lookups by
 * `tokenHash` drive email-verification confirmation.
 *
 * @extends CycleRepository<EmailVerification>
 * @implements RepositoryInterface<EmailVerification>
 */
final class EmailVerificationRepository extends CycleRepository implements RepositoryInterface
{
    public function __construct(ORMInterface $orm, UnitOfWorkInterface $unitOfWork)
    {
        parent::__construct(EmailVerification::class, $orm, $unitOfWork);
    }
}
