<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\GrantRequests;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_values;
use function is_array;

/**
 * `POST /agents/grants/request`: the agent asks for capabilities (with the constraints it offers); what
 * the policy auto-approves is active at once, the rest waits for the owner in one approval (AAP's
 * `{agent_id, agent_capability_grants, approval}`).
 */
final class RequestGrantsEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly AgentAuthenticator $authenticator, private readonly GrantRequests $requests)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $asked = $input->get('capabilities');
        $context = $this->client($input);
        try {
            $principal = $this->agent($this->authenticator, $input);
            if (!is_array($asked)) {
                throw new AgentException(AgentException::INVALID_INPUT, 'capabilities is a list of capability names or {name, constraints}.');
            }
            $requested = $this->requests->request($principal->agent, array_values($asked), self::text($input, 'preferred_method'), self::text($input, 'binding_message'), self::text($input, 'reason'), true, $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return new Result(200, $this->requests->response($principal->agent, $requested['grants'], $requested['approval']), self::NO_STORE);
    }
}
