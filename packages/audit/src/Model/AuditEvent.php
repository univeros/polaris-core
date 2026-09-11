<?php

declare(strict_types=1);

namespace Polaris\Audit\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * One row of `polaris_audit_event`: what happened, to whom, by whom, where from, plus the event's own
 * data (redacted, never a secret) and, with the hash chain on, the link to the previous row.
 */
final class AuditEvent
{
    public const string ACTOR_USER = 'user';
    public const string ACTOR_ADMIN = 'admin';
    public const string ACTOR_API_KEY = 'api_key';
    public const string ACTOR_AGENT = 'agent';
    public const string ACTOR_SYSTEM = 'system';

    public string $id = '';
    public string $name = '';
    public DateTimeImmutable $occurredAt;
    public string $actorType = self::ACTOR_SYSTEM;
    public ?string $actorId = null;
    public ?string $subjectId = null;
    public ?string $organizationId = null;
    public ?string $sessionId = null;
    public ?string $ip = null;
    public ?string $userAgent = null;
    /** @var array<string, mixed> */
    public array $data = [];
    public ?string $requestId = null;
    public ?string $prevHash = null;
    public ?string $hash = null;

    /**
     * @param array<string, mixed> $data
     */
    public static function of(
        string $name,
        DateTimeImmutable $occurredAt,
        ?string $actorId = null,
        string $actorType = self::ACTOR_SYSTEM,
        ?string $subjectId = null,
        ?string $organizationId = null,
        ?string $sessionId = null,
        ?string $ip = null,
        ?string $userAgent = null,
        array $data = [],
        ?string $requestId = null,
    ): self {
        $event = new self();
        $event->name = $name;
        $event->occurredAt = $occurredAt;
        $event->actorId = $actorId;
        $event->actorType = $actorId === null ? self::ACTOR_SYSTEM : $actorType;
        $event->subjectId = $subjectId;
        $event->organizationId = $organizationId;
        $event->sessionId = $sessionId;
        $event->ip = $ip;
        $event->userAgent = $userAgent;
        $event->data = $data;
        $event->requestId = $requestId;

        return $event;
    }

    /**
     * The wire shape of an event, as the query routes answer it.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'occurred_at' => $this->occurredAt->format(DATE_ATOM),
            'actor_type' => $this->actorType,
            'actor_id' => $this->actorId,
            'subject_id' => $this->subjectId,
            'organization_id' => $this->organizationId,
            'session_id' => $this->sessionId,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'data' => $this->data,
            'request_id' => $this->requestId,
        ];
    }
}
