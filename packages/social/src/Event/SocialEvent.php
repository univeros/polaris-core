<?php

declare(strict_types=1);

namespace Polaris\Social\Event;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * What happened to a provider account, as a PSR-14 event the host may listen to and as the audit record
 * the audit plugin keeps (`social.*`): the name, the user, the provider, and the details.
 */
final readonly class SocialEvent implements Auditable
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public string $name,
        public ?string $userId,
        public string $provider,
        public array $data = [],
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of($this->name, $clock->now(), $this->userId, $this->userId === null ? AuditEvent::ACTOR_SYSTEM : AuditEvent::ACTOR_USER, $this->userId, null, null, $this->ip, $this->userAgent, ['provider' => $this->provider, ...$this->data]);
    }
}
