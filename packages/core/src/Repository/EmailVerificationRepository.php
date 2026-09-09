<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\EmailVerification;
use Polaris\Schema\Definitions\EmailVerificationSchema;

/**
 * @extends GenericRepository<EmailVerification>
 */
final class EmailVerificationRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, EmailVerificationSchema::define(), $identities);
    }
}
