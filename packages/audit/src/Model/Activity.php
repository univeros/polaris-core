<?php

declare(strict_types=1);

namespace Polaris\Audit\Model;

use DateTimeImmutable;

/**
 * A user's last activity (`polaris_audit_activity`), kept beside the user rather than on them.
 */
final class Activity
{
    public string $userId = '';
    public DateTimeImmutable $lastActiveAt;
}
