<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\MfaFactor;
use Polaris\Schema\Definitions\MfaFactorSchema;

/**
 * @extends GenericRepository<MfaFactor>
 */
final class MfaFactorRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, MfaFactorSchema::define(), $identities);
    }
}
