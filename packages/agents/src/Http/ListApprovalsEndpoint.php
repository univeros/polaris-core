<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Agents;
use Polaris\Agents\Approvals;
use Polaris\Agents\GrantRequests;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /agents/approvals`: the pending approvals of the caller's agents (the `in_app` method: the owner's
 * own client lists and decides), each with the agent and the grants it covers.
 */
final class ListApprovalsEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Approvals $approvals, private readonly Agents $agents, private readonly GrantRequests $requests, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $data = [];
        foreach ($this->approvals->pendingFor($this->managedAgents($this->agents, $token, $this->gate)) as $approval) {
            $data[] = $this->requests->describe($approval, $this->agents->find($approval->agentId));
        }

        return new Result(200, ['data' => $data], self::NO_STORE);
    }
}
