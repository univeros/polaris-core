<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Organization;
use Polaris\Schema\Definitions\OrganizationSchema;

/**
 * @extends GenericRepository<Organization>
 */
final class OrganizationRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, OrganizationSchema::define(), $identities);
    }
}
