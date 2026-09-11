<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

/**
 * Dispatched after every delivery, recorded by the audit plugin as `messaging.sent`: the channel, the
 * template, a hash of the recipient and the provider's id; never the body.
 */
final readonly class MessageSent implements Auditable
{
    public const string NAME = 'messaging.sent';

    public function __construct(
        public string $kind,
        public string $template,
        public string $recipientHash,
        public string $channel,
        public ?string $providerId,
        public ?string $organizationId,
        public bool $fallback,
    ) {
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of(self::NAME, $clock->now(), null, AuditEvent::ACTOR_SYSTEM, null, $this->organizationId, data: [
            'kind' => $this->kind,
            'template' => $this->template,
            'recipient_hash' => $this->recipientHash,
            'channel' => $this->channel,
            'provider_id' => $this->providerId,
            'fallback' => $this->fallback,
        ]);
    }
}
