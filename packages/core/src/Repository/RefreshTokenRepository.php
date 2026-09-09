<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\RefreshToken;
use Polaris\Schema\Definitions\RefreshTokenSchema;

/**
 * @extends GenericRepository<RefreshToken>
 */
final class RefreshTokenRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, RefreshTokenSchema::define(), $identities);
    }
}
