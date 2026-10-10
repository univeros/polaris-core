<?php

declare(strict_types=1);

namespace Polaris\Agents\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\KillSwitch;
use Polaris\Agents\Model\Agent;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /admin/agents/{id}/revoke`: an operator pulls the kill switch on any agent in their scope.
 */
final class AdminRevokeAgentEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Agents $agents, private readonly KillSwitch $killSwitch)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $agent = $this->agents->find((string) $input->get('id'));
        $principal = $this->authorize($input, Capability::Own, $agent?->organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        if (!$agent instanceof Agent) {
            return $this->missing('The agent does not exist.');
        }
        $context = $this->client($input);
        try {
            $receipt = $this->killSwitch->revoke($agent, $principal->type === Principal::TYPE_API_KEY ? null : $principal->id, 'admin', $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->conflict($exception->detail);
        }

        return $this->respond(200, ['data' => [...$agent->toArray(), 'sealed_receipt' => $receipt->toArray()]]);
    }
}
