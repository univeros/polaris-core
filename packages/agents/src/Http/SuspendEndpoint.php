<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Agents;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Model\Agent;

/**
 * `POST /agents/{id}/suspend`.
 */
final class SuspendEndpoint extends StatusEndpoint
{
    #[Override]
    protected function transition(Agents $agents, Agent $agent): string
    {
        $agents->suspend($agent);

        return AuditNames::SUSPENDED;
    }
}
