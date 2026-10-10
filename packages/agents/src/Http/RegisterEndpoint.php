<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Registrations;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function is_array;

/**
 * `POST /agents/register`: the caller registers an agent for themselves, or for an organization they may
 * update; the client secret, when the agent has one, is in this response only.
 */
final class RegisterEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Registrations $registrations, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $asked = $input->get('capabilities', []);
        if (!is_array($asked)) {
            return $this->refuse(new AgentException(AgentException::INVALID_INPUT, 'capabilities is a list of capability names or {name, constraints}.'));
        }
        $context = $this->client($input);
        try {
            [$ownerType, $ownerId, $organizationId] = $this->owner($input, $token, $this->gate);
            $registered = $this->registrations->register($input->all(), $ownerType, $ownerId, $organizationId, $this->actorId($token), array_values($asked), $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return new Result(201, $this->registrations->response($registered), self::NO_STORE);
    }
}
