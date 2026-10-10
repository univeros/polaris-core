<?php

declare(strict_types=1);

namespace Polaris\Agents\Event;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * What happened to or through an agent, as a PSR-14 event the host may listen to and as the audit
 * record (`agent.*`): where the agent acts (an execution, a grant request) the actor is the agent
 * (`actor_type = agent`) and the subject its owner; where the owner acts (register, decide, revoke)
 * the actor is the user and the subject the agent's owner.
 */
final readonly class AgentEvent implements Auditable
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public string $name,
        public string $agentId,
        public string $actorType,
        public ?string $actorId,
        public ?string $subjectId,
        public ?string $organizationId = null,
        public array $data = [],
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {
    }

    /**
     * The agent acting (its id as the actor, the owner as the subject).
     *
     * @param array<string, mixed> $data
     */
    public static function byAgent(string $name, string $agentId, ?string $ownerUserId, ?string $organizationId, array $data = [], ?string $ip = null, ?string $userAgent = null): self
    {
        return new self($name, $agentId, AuditEvent::ACTOR_AGENT, $agentId, $ownerUserId, $organizationId, $data, $ip, $userAgent);
    }

    /**
     * A person acting on the agent.
     *
     * @param array<string, mixed> $data
     */
    public static function byUser(string $name, string $agentId, string $userId, ?string $organizationId, array $data = [], ?string $ip = null, ?string $userAgent = null): self
    {
        return new self($name, $agentId, AuditEvent::ACTOR_USER, $userId, $userId, $organizationId, $data, $ip, $userAgent);
    }

    /**
     * The system acting (a listener, the auto-approval policy).
     *
     * @param array<string, mixed> $data
     */
    public static function bySystem(string $name, string $agentId, ?string $ownerUserId, ?string $organizationId, array $data = []): self
    {
        return new self($name, $agentId, AuditEvent::ACTOR_SYSTEM, null, $ownerUserId, $organizationId, $data);
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of($this->name, $clock->now(), $this->actorId, $this->actorType, $this->subjectId, $this->organizationId, null, $this->ip, $this->userAgent, ['agent_id' => $this->agentId, ...$this->data]);
    }
}
