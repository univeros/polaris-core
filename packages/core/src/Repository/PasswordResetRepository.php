<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\PasswordReset;
use Polaris\Schema\Definitions\PasswordResetSchema;

/**
 * @extends GenericRepository<PasswordReset>
 */
final class PasswordResetRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, PasswordResetSchema::define(), $identities);
    }
}
