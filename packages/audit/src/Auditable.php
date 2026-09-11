<?php

declare(strict_types=1);

namespace Polaris\Audit;

use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * An event of another package that knows its own audit shape; the recorder writes it as it is (its
 * name must be in the catalog).
 */
interface Auditable
{
    public function toAuditEvent(ClockInterface $clock): AuditEvent;
}
