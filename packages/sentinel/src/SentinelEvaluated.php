<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Override;
use Polaris\Audit\Auditable;
use Polaris\Audit\Model\AuditEvent;
use Psr\Clock\ClockInterface;

use function hash;

/**
 * Recorded as `sentinel.evaluated` whenever a signal spoke: the kind, the score, the action (and whether
 * it was enforced), the signals and their reasons, the recipient hashed, the IP.
 */
final readonly class SentinelEvaluated implements Auditable
{
    public const string NAME = 'sentinel.evaluated';

    public function __construct(public Attempt $attempt, public Decision $decision)
    {
    }

    #[Override]
    public function toAuditEvent(ClockInterface $clock): AuditEvent
    {
        return AuditEvent::of(self::NAME, $clock->now(), null, AuditEvent::ACTOR_SYSTEM, null, null, null, $this->attempt->ip, $this->attempt->userAgent, [
            'kind' => $this->attempt->kind,
            'email_hash' => $this->attempt->email === null ? null : hash('sha256', $this->attempt->email),
            'score' => $this->decision->score,
            'action' => $this->decision->action,
            'enforced' => $this->decision->enforced,
            'signals' => $this->decision->signals(),
            'reasons' => $this->decision->reasons(),
        ]);
    }
}
