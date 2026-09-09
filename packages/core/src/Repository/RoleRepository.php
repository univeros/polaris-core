<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Role;
use Polaris\Schema\Definitions\RoleSchema;

/**
 * @extends GenericRepository<Role>
 */
final class RoleRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, RoleSchema::define(), $identities);
    }
}
