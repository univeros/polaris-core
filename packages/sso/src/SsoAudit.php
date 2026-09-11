<?php

declare(strict_types=1);

namespace Polaris\Sso;

use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Recorder;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;

/**
 * Records the `sso.*` events: a user's action on their organization's providers (actor `user`), an
 * operator's (actor `admin` or `api_key`), or the engine's own (actor `system`).
 *
 * @see AuditNames
 */
final class SsoAudit
{
    public function __construct(private readonly Recorder $recorder, private readonly ClockInterface $clock)
    {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function record(string $name, string $actorType, ?string $actorId, ?string $subjectId, ?string $organizationId, array $data = [], ?ClientContext $client = null): void
    {
        $this->recorder->record(AuditEvent::of($name, $this->clock->now(), $actorId, $actorType, $subjectId, $organizationId, null, $client?->ip, $client?->userAgent, $data));
    }
}
