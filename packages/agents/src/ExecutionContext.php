<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Grant;

/**
 * What a capability handler is told about the execution it runs in: the agent, the grant it runs
 * under (constraints, remaining budget after this execution), the capability and the arguments.
 */
final readonly class ExecutionContext
{
    /**
     * @param array<string, mixed> $arguments
     */
    public function __construct(
        public Agent $agent,
        public Grant $grant,
        public Capability $capability,
        public array $arguments,
        public string $inputHash,
    ) {
    }
}
