<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Wiring\Graph;

/**
 * A plugin that adds MFA factor types to core's gate: the challenge verifier asks for them on its first
 * verification. Built with the graph, so a type may use the plugin's own services, the MFA ones included.
 */
interface MfaFactorTypeProvider
{
    /**
     * @return list<MfaFactorType>
     */
    public function mfaFactorTypes(Graph $graph): array;
}
