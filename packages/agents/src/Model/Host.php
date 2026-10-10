<?php

declare(strict_types=1);

namespace Polaris\Agents\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A host (`polaris_agent_host`): a runtime that enrols agents (a Claude Code install, a worker, a cron
 * box) with its enrolment token (`peh_...`, stored as a keyed hash), under its owner, with the
 * capabilities every agent it enrols asks for.
 */
final class Host
{
    public string $id = '';
    public string $ownerType = Agent::OWNER_USER;
    public string $ownerId = '';
    public ?string $organizationId = null;
    public string $name = '';
    public string $enrollmentTokenHash = '';
    /** @var list<string> */
    public array $defaultCapabilities = [];
    public string $createdBy = '';
    public ?DateTimeImmutable $revokedAt = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'owner_type' => $this->ownerType,
            'owner_id' => $this->ownerId,
            'organization_id' => $this->organizationId,
            'name' => $this->name,
            'default_capabilities' => $this->defaultCapabilities,
            'created_by' => $this->createdBy,
            'revoked_at' => $this->revokedAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
