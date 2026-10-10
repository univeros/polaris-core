<?php

declare(strict_types=1);

namespace Polaris\Agent;

use RuntimeException;

/**
 * The wait for an approval ended without the grants: `denied`, `expired` (or the attempts ran out),
 * or `cancelled` by the caller.
 */
final class ApprovalException extends RuntimeException
{
    public const string DENIED = 'denied';
    public const string EXPIRED = 'expired';
    public const string CANCELLED = 'cancelled';

    /**
     * @param array<string, mixed> $approval
     */
    public function __construct(public readonly string $outcome, public readonly array $approval, string $message)
    {
        parent::__construct($message);
    }
}
