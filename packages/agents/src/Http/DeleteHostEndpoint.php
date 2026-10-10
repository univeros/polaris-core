<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Hosts;
use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `DELETE /agents/hosts/{id}`: the host's enrolment token stops working; the agents it enrolled stay.
 */
final class DeleteHostEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Hosts $hosts, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $host = $this->hosts->find((string) $input->get('id'));
        $own = $host !== null && $host->ownerType === Agent::OWNER_USER && $host->ownerId === $this->actorId($token);
        $organization = $host !== null && $host->ownerType === Agent::OWNER_ORGANIZATION && $host->ownerId === $this->actorOrg($token) && $this->gate->allows($token, self::ORGANIZATION_PERMISSION);
        if ($host === null || $host->revokedAt !== null || (!$own && !$organization)) {
            return $this->refuse(new AgentException(AgentException::NOT_FOUND, 'The host does not exist.'));
        }
        $this->hosts->revoke($host);

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
