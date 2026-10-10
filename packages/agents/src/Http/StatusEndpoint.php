<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `POST /agents/{id}/suspend` and `/resume`: the owner pauses an agent (its tokens and JWTs are
 * refused until it is resumed) or resumes it.
 */
abstract class StatusEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Agents $agents, private readonly Gate $gate, private readonly EventDispatcherInterface $events)
    {
    }

    abstract protected function transition(Agents $agents, Agent $agent): string;

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $agent = $this->managed($this->agents, $input, $token, $this->gate);
            $name = $this->transition($this->agents, $agent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(AgentEvent::byUser($name, $agent->id, $this->actorId($token), $agent->organizationId, ['name' => $agent->name], $context->ip, $context->userAgent));

        return $this->respond(200, ['data' => $agent->toArray()]);
    }
}
