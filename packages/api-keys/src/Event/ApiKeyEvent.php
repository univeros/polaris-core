<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Event;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * What happened to an API key, as a PSR-14 event the host may listen to and as the audit record the
 * audit plugin keeps (`api_keys.*`): the name, the acting user, the key, its owner and the details.
 */
final readonly class ApiKeyEvent implements Auditable
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public string $name,
        public string $actorId,
        public string $keyId,
        public string $ownerType,
        public string $ownerId,
        public ?string $organizationId,
        public array $data = [],
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of($this->name, $clock->now(), $this->actorId, AuditEvent::ACTOR_USER, $this->keyId, $this->organizationId, null, $this->ip, $this->userAgent, ['owner_type' => $this->ownerType, 'owner_id' => $this->ownerId, ...$this->data]);
    }
}
