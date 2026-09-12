<?php

declare(strict_types=1);

namespace Polaris\Scim;

use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Recorder;
use Polaris\Scim\Model\Connection;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;

/**
 * Records the `scim.*` events: a connection's action (actor `api_key`, the connection id) or a user's
 * on their organization's connections (actor `user`).
 */
final class ScimAudit
{
    public function __construct(private readonly Recorder $recorder, private readonly ClockInterface $clock)
    {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function record(string $name, Connection $connection, ?string $subjectId, array $data = [], ?ClientContext $client = null): void
    {
        $this->recorder->record(AuditEvent::of($name, $this->clock->now(), $connection->id, AuditEvent::ACTOR_API_KEY, $subjectId, $connection->organizationId, null, $client?->ip, $client?->userAgent, [...$data, 'connection_name' => $connection->name]));
    }

    /**
     * @param array<string, mixed> $data
     */
    public function recordUser(string $name, string $userId, Connection $connection, array $data = [], ?ClientContext $client = null): void
    {
        $this->recorder->record(AuditEvent::of($name, $this->clock->now(), $userId, AuditEvent::ACTOR_USER, $connection->id, $connection->organizationId, null, $client?->ip, $client?->userAgent, [...$data, 'connection_name' => $connection->name]));
    }
}
