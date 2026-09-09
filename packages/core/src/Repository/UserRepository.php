<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\User;
use Polaris\Schema\Definitions\UserSchema;

/**
 * @extends GenericRepository<User>
 */
final class UserRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, UserSchema::define(), $identities);
    }
}
