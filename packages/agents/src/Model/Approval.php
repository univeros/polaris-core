<?php

declare(strict_types=1);

namespace Polaris\Agents\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * An approval (`polaris_agent_approval`): a person's pending decision on one or more grants an agent
 * asked for. The method only changes how the owner finds it (a user code on the host's approval
 * page, a push from the `agent.grant.requested` event, the owner's own client listing it); the
 * strength is what the riskiest capability requires of the deciding session.
 */
final class Approval
{
    public const string METHOD_DEVICE = 'device_authorization';
    public const string METHOD_CIBA = 'ciba';
    public const string METHOD_IN_APP = 'in_app';
    public const array METHODS = [self::METHOD_DEVICE, self::METHOD_CIBA, self::METHOD_IN_APP];

    public const string STATUS_PENDING = 'pending';
    public const string STATUS_APPROVED = 'approved';
    public const string STATUS_DENIED = 'denied';
    public const string STATUS_EXPIRED = 'expired';
    public const string STATUS_CANCELLED = 'cancelled';

    public string $id = '';
    public string $agentId = '';
    /** @var list<string> */
    public array $grantIds = [];
    public string $method = self::METHOD_IN_APP;
    public string $strength = 'session';
    public string $userCode = '';
    public ?string $bindingMessage = null;
    public string $status = self::STATUS_PENDING;
    public ?string $decidedBy = null;
    public DateTimeImmutable $expiresAt;
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    public function isPending(DateTimeImmutable $now): bool
    {
        return $this->status === self::STATUS_PENDING && $this->expiresAt > $now;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'agent_id' => $this->agentId,
            'grant_ids' => $this->grantIds,
            'method' => $this->method,
            'strength' => $this->strength,
            'user_code' => $this->userCode,
            'binding_message' => $this->bindingMessage,
            'status' => $this->status,
            'decided_by' => $this->decidedBy,
            'expires_at' => $this->expiresAt->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
