<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Invitation;
use Polaris\Schema\Definitions\InvitationSchema;

/**
 * @extends GenericRepository<Invitation>
 */
final class InvitationRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, InvitationSchema::define(), $identities);
    }
}
