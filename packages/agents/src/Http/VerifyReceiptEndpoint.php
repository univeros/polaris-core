<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Receipts;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\OAuthResolver;

/**
 * `GET /agents/receipts/{id}/verify`: recomputes the receipt's hash, verifies its signature with core's
 * key and checks its link to the previous receipt. For the agent's owner, or the agent itself.
 */
final class VerifyReceiptEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Receipts $receipts, private readonly Agents $agents, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $receipt = $this->receipts->find((string) $input->get('id'));
        $agent = $receipt === null ? null : $this->agents->find($receipt->agentId);
        $self = $agent !== null && $token->getMetadata(OAuthResolver::CLAIM_CLIENT) === $agent->id;
        if ($receipt === null || $agent === null || (!$self && !$this->manages($agent, $token, $this->gate))) {
            return $this->refuse(new AgentException(AgentException::NOT_FOUND, 'The receipt does not exist.'));
        }

        return new Result(200, ['data' => [...$this->receipts->verify($receipt), 'receipt' => $receipt->toArray()]], self::NO_STORE);
    }
}
