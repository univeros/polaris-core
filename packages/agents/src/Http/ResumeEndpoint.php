<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Agents;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Model\Agent;

/**
 * `POST /agents/{id}/resume`.
 */
final class ResumeEndpoint extends StatusEndpoint
{
    #[Override]
    protected function transition(Agents $agents, Agent $agent): string
    {
        $agents->resume($agent);

        return AuditNames::RESUMED;
    }
}
