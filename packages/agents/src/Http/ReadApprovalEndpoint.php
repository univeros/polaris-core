<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Approvals;
use Polaris\Agents\GrantRequests;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /agents/approvals/code?user_code=`: what the host's approval page shows a signed-in owner for the user
 * code they typed (dashes and case do not matter): the agent, the grants asked, the strength needed.
 */
final class ReadApprovalEndpoint extends AgentsEndpoint
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
        $approval = $this->approvals->byUserCode((string) $input->get('user_code'));
        $agent = $approval === null ? null : $this->agents->find($approval->agentId);
        if ($approval === null || $agent === null || !$this->manages($agent, $token, $this->gate)) {
            return $this->refuse(new AgentException(AgentException::NOT_FOUND, 'No pending approval has this code.'));
        }

        return new Result(200, ['data' => $this->requests->describe($approval, $agent)], self::NO_STORE);
    }
}
