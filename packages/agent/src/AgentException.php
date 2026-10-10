<?php

declare(strict_types=1);

namespace Polaris\Agent;

use RuntimeException;

/**
 * A refused call: the HTTP status, the RFC 9457 problem document when the server sent one, and its
 * `error` code (`invalid_jwt`, `capability_not_granted`, `constraint_violated` with `violations`, ...).
 */
final class AgentException extends RuntimeException
{
    /**
     * @param array<string, mixed>|null $problem
     */
    public function __construct(
        string $message,
        public readonly int $status,
        public readonly ?array $problem = null,
        public readonly string $error = 'request_failed',
    ) {
        parent::__construct($message, $status);
    }
}
