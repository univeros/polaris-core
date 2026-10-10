<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Grants;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `DELETE /agents/grants/{id}`: the owner revokes a grant; it takes effect at the agent's next request.
 */
final class DeleteGrantEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Grants $grants, private readonly Agents $agents, private readonly Gate $gate, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $grant = $this->grants->find((string) $input->get('id'));
        $agent = $grant === null ? null : $this->agents->find($grant->agentId);
        if ($grant === null || $agent === null || !$this->manages($agent, $token, $this->gate)) {
            return $this->refuse(new AgentException(AgentException::NOT_FOUND, 'The grant does not exist.'));
        }
        try {
            $this->grants->revoke($grant);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }
        $this->grants->syncClientScopes($agent);
        $context = $this->client($input);
        $this->events->dispatch(AgentEvent::byUser(AuditNames::GRANT_REVOKED, $agent->id, $this->actorId($token), $agent->organizationId, ['capability' => $grant->capability, 'grant_id' => $grant->id], $context->ip, $context->userAgent));

        return $this->respond(200, ['data' => $grant->toArray()]);
    }
}
