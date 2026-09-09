<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\RecoveryCode;
use Polaris\Schema\Definitions\RecoveryCodeSchema;

/**
 * @extends GenericRepository<RecoveryCode>
 */
final class RecoveryCodeRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, RecoveryCodeSchema::define(), $identities);
    }
}
