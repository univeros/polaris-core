<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Agents;
use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /agents`: the caller's agents, and their active organization's when they may update it.
 */
final class ListAgentsEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Agents $agents, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => array_map(static fn(Agent $agent): array => $agent->toArray(), $this->managedAgents($this->agents, $token, $this->gate))]);
    }
}
