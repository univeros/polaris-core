<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Polaris\Audit\Model\AuditEvent;

/**
 * Where audit events go: the database (the default), a PSR-3 logger, a JSON-lines file, an HTTP
 * endpoint. Sinks configured on the plugin are static; drains are the same idea per organization,
 * configured at runtime.
 */
interface AuditSink
{
    public function write(AuditEvent ...$events): void;
}
