<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Executor;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /agents/execute {capability, arguments}` (`input` is accepted as an alias): the capability's
 * handler runs under the agent's grant, within its constraints and budget, and a receipt is appended,
 * all in one transaction.
 */
final class ExecuteEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly AgentAuthenticator $authenticator, private readonly Executor $executor)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $context = $this->client($input);
        try {
            $principal = $this->agent($this->authenticator, $input);
            $execution = $this->executor->execute($principal, self::text($input, 'capability') ?? '', $input->get('arguments', $input->get('input', [])), $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return new Result(200, $execution->toArray(), self::NO_STORE);
    }
}
