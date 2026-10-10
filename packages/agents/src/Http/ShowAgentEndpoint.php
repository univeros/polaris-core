<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Grants;
use Polaris\Agents\Model\Grant;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /agents/{id}`: one of the caller's agents, with its grants.
 */
final class ShowAgentEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Agents $agents, private readonly Grants $grants, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $agent = $this->managed($this->agents, $input, $token, $this->gate);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => [...$agent->toArray(), 'grants' => array_map(static fn(Grant $grant): array => $grant->toArray(), $this->grants->forAgent($agent))]]);
    }
}
