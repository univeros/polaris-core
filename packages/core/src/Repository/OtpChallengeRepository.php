<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\OtpChallenge;
use Polaris\Schema\Definitions\OtpChallengeSchema;

/**
 * @extends GenericRepository<OtpChallenge>
 */
final class OtpChallengeRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, OtpChallengeSchema::define(), $identities);
    }
}
