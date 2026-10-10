<?php

declare(strict_types=1);

namespace Polaris\Agents\Model;

use DateTimeImmutable;
use DateTimeZone;

use const DATE_ATOM;

/**
 * A receipt (`polaris_agent_receipt`): one per execution, in a hash chain per agent (`seq`,
 * `prev_hash`, `hash` over the canonical JSON of the fields), signed with core's key. The arguments
 * are kept as a hash only. The final receipt of a revoked agent has the outcome `sealed`.
 */
final class Receipt
{
    public const string OUTCOME_SUCCESS = 'success';
    public const string OUTCOME_FAILED = 'failed';
    public const string OUTCOME_SEALED = 'sealed';

    public string $id = '';
    public string $agentId = '';
    public int $seq = 0;
    public ?string $grantId = null;
    public ?string $capability = null;
    public string $inputHash = '';
    public string $outcome = self::OUTCOME_SUCCESS;
    public ?int $budgetBefore = null;
    public ?int $budgetAfter = null;
    public ?string $prevHash = null;
    public string $hash = '';
    public string $signature = '';
    public DateTimeImmutable $createdAt;

    /**
     * The fields the hash covers, in the order the canonical JSON sorts them.
     *
     * @return array<string, mixed>
     */
    public function hashed(): array
    {
        return [
            'agent_id' => $this->agentId,
            'budget_after' => $this->budgetAfter,
            'budget_before' => $this->budgetBefore,
            'capability' => $this->capability,
            'created_at' => $this->createdAt->setTimezone(new DateTimeZone('UTC'))->format(DATE_ATOM),
            'grant_id' => $this->grantId,
            'id' => $this->id,
            'input_hash' => $this->inputHash,
            'outcome' => $this->outcome,
            'prev_hash' => $this->prevHash,
            'seq' => $this->seq,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [...$this->hashed(), 'hash' => $this->hash, 'signature' => $this->signature];
    }
}
