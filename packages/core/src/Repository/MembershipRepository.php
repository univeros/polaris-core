<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Membership;
use Polaris\Schema\Definitions\MembershipSchema;

/**
 * @extends GenericRepository<Membership>
 */
final class MembershipRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, MembershipSchema::define(), $identities);
    }
}
