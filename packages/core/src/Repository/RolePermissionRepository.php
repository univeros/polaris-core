<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\RolePermission;
use Polaris\Schema\Definitions\RolePermissionSchema;

/**
 * @extends GenericRepository<RolePermission>
 */
final class RolePermissionRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, RolePermissionSchema::define(), $identities);
    }
}
