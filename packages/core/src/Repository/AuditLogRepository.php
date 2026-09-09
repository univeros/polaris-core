<?php

declare(strict_types=1);

namespace Polaris\Repository;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\AuditLogEntry;
use Polaris\Schema\Definitions\AuditLogEntrySchema;

/**
 * @extends GenericRepository<AuditLogEntry>
 */
final class AuditLogRepository extends GenericRepository
{
    public function __construct(DatabaseAdapter $database, IdentityMap $identities)
    {
        parent::__construct($database, AuditLogEntrySchema::define(), $identities);
    }
}
