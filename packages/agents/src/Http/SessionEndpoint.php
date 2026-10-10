<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Grants;
use Polaris\Agents\Hosts;
use Polaris\Agents\Model\Grant;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /agents/session` (AAP's status): the agent, its mode and owner, its host, and its grants with
 * their remaining budgets.
 */
final class SessionEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly AgentAuthenticator $authenticator, private readonly Grants $grants, private readonly Hosts $hosts)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $principal = $this->agent($this->authenticator, $input);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }
        $agent = $principal->agent;
        $host = $agent->hostId === null ? null : $this->hosts->find($agent->hostId);

        return new Result(200, ['data' => [
            'agent' => $agent->toArray(),
            'mode' => $agent->mode,
            'owner' => ['type' => $agent->ownerType, 'id' => $agent->ownerId],
            'organization_id' => $agent->organizationId,
            'host' => $host === null ? null : ['id' => $host->id, 'name' => $host->name],
            'authenticated_via' => $principal->via,
            'grants' => array_map(static fn(Grant $grant): array => $grant->toArray(), $this->grants->forAgent($agent)),
        ]], self::NO_STORE);
    }
}
