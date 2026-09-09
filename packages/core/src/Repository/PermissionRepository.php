<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Permission;
use Polaris\Schema\Definitions\PermissionSchema;

/**
 * @extends GenericRepository<Permission>
 */
final class PermissionRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, PermissionSchema::define(), $identities);
    }
}
