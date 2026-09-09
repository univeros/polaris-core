<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\MembershipRole;
use Polaris\Schema\Definitions\MembershipRoleSchema;

/**
 * @extends GenericRepository<MembershipRole>
 */
final class MembershipRoleRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, MembershipRoleSchema::define(), $identities);
    }
}
