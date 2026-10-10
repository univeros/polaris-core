<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Hosts;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_values;
use function is_array;

/**
 * `POST /agents/hosts`: a host for the caller (or an organization they may update); the enrolment
 * token is in this response only.
 */
final class CreateHostEndpoint extends AgentsEndpoint
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
        $defaults = $input->get('default_capabilities', []);
        if (!is_array($defaults)) {
            return $this->refuse(new AgentException(AgentException::INVALID_INPUT, 'default_capabilities is a list of capability names.'));
        }
        try {
            [$ownerType, $ownerId, $organizationId] = $this->owner($input, $token, $this->gate);
            [$host, $enrollmentToken] = $this->hosts->create($ownerType, $ownerId, $organizationId, $this->actorId($token), $input->get('name'), array_values($defaults));
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return new Result(201, ['data' => [...$host->toArray(), 'enrollment_token' => $enrollmentToken]], self::NO_STORE);
    }
}
