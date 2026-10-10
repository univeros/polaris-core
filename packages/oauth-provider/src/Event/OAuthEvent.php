<?php

declare(strict_types=1);

namespace Polaris\OAuth\Event;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * What happened at the provider, as a PSR-14 event the host may listen to and as the audit record the
 * audit plugin keeps (`oauth.*`): the name, the user (when one acted or was acted for), the client
 * and the details.
 */
final readonly class OAuthEvent implements Auditable
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public string $name,
        public ?string $userId,
        public string $clientId,
        public ?string $organizationId = null,
        public array $data = [],
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of($this->name, $clock->now(), $this->userId, $this->userId === null ? AuditEvent::ACTOR_SYSTEM : AuditEvent::ACTOR_USER, $this->userId, $this->organizationId, null, $this->ip, $this->userAgent, ['client_id' => $this->clientId, ...$this->data]);
    }
}
