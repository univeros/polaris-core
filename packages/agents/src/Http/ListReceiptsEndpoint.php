<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Model\Receipt;
use Polaris\Agents\Receipts;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;
use function count;
use function is_numeric;

/**
 * `GET /agents/{id}/receipts`: the agent's receipt chain, oldest first, `after` a sequence number,
 * at most `limit` (100, up to 200) receipts; exportable as a chain.
 */
final class ListReceiptsEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Agents $agents, private readonly Receipts $receipts, private readonly Gate $gate)
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
        $after = $input->get('after');
        $limit = $input->get('limit');
        $receipts = $this->receipts->forAgent($agent, is_numeric($after) ? (int) $after : 0, is_numeric($limit) ? (int) $limit : 100);
        $last = $receipts === [] ? null : $receipts[count($receipts) - 1];

        return $this->respond(200, ['data' => array_map(static fn(Receipt $receipt): array => $receipt->toArray(), $receipts), 'next_cursor' => $last?->seq, 'has_more' => $last !== null && $this->receipts->forAgent($agent, $last->seq, 1) !== []]);
    }
}
