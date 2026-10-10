<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Grant;

/**
 * An execution that passed every check and may be run: the grant it runs under, the arguments, their
 * hash and what the budget will be charged.
 */
final readonly class Evaluation
{
    /**
     * @param array<string, mixed> $arguments
     */
    public function __construct(
        public AuthenticatedAgent $principal,
        public Capability $capability,
        public Grant $grant,
        public array $arguments,
        public string $inputHash,
        public int $cost,
    ) {
    }
}
