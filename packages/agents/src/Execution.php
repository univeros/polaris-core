<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Receipt;

/**
 * What an execution produced: the handler's result, the receipt, the grant as it stands after the
 * budget was spent, and whether that spent it.
 */
final readonly class Execution
{
    public function __construct(
        public mixed $result,
        public Receipt $receipt,
        public Grant $grant,
        public bool $exhausted,
    ) {
    }

    /**
     * The `POST /agents/execute` body.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['data' => $this->result, 'receipt' => ['id' => $this->receipt->id, 'seq' => $this->receipt->seq, 'hash' => $this->receipt->hash]];
    }
}
