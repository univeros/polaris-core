<?php

declare(strict_types=1);

namespace Polaris\Agents\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A capability grant (`polaris_agent_grant`): an agent may execute a capability within the constraints
 * on its arguments and a budget (a count of executions, or an amount summed from one argument),
 * until it expires, is revoked or is exhausted. Pending until a person (or the auto-approval policy)
 * approves it.
 */
final class Grant
{
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_PENDING = 'pending';
    public const string STATUS_DENIED = 'denied';
    public const string STATUS_REVOKED = 'revoked';
    public const string STATUS_EXHAUSTED = 'exhausted';

    public const string BUDGET_COUNT = 'count';
    public const string BUDGET_AMOUNT = 'amount';

    public const string VIA_AUTO = 'auto';

    public string $id = '';
    public string $agentId = '';
    public string $capability = '';
    /** @var array<string, array<string, mixed>> argument => operators */
    public array $constraints = [];
    public ?int $budgetTotal = null;
    public ?int $budgetRemaining = null;
    public ?string $budgetKind = null;
    public ?string $budgetField = null;
    public string $status = self::STATUS_PENDING;
    public ?string $grantedBy = null;
    public ?string $approvedVia = null;
    public ?string $approvalId = null;
    public ?DateTimeImmutable $expiresAt = null;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    public function isLive(DateTimeImmutable $now): bool
    {
        return $this->status === self::STATUS_ACTIVE && ($this->expiresAt === null || $this->expiresAt > $now);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'agent_id' => $this->agentId,
            'capability' => $this->capability,
            'constraints' => (object) $this->constraints,
            'budget' => $this->budgetKind === null ? null : ['kind' => $this->budgetKind, 'total' => $this->budgetTotal, 'remaining' => $this->budgetRemaining, 'field' => $this->budgetField],
            'status' => $this->status,
            'granted_by' => $this->grantedBy,
            'approved_via' => $this->approvedVia,
            'approval_id' => $this->approvalId,
            'expires_at' => $this->expiresAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
