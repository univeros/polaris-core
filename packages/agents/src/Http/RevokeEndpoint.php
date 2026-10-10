<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\KillSwitch;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /agents/{id}/revoke`: the kill switch. The agent's tokens, grants and pending approvals end
 * and its receipt chain is sealed with a final receipt.
 */
final class RevokeEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Agents $agents, private readonly KillSwitch $killSwitch, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $context = $this->client($input);
        try {
            $agent = $this->managed($this->agents, $input, $token, $this->gate);
            $receipt = $this->killSwitch->revoke($agent, $this->actorId($token), 'owner', $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => [...$agent->toArray(), 'sealed_receipt' => $receipt->toArray()]]);
    }
}
