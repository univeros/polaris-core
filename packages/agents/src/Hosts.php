<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Host;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Jwt;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function count;
use function is_string;
use function mb_strlen;
use function random_bytes;
use function str_starts_with;
use function trim;

/**
 * The hosts (`polaris_agent_host`): created by an owner with an enrolment token shown once and stored as
 * a keyed hash (pepper context `agent_host`); a host presents it as a bearer at `POST /agents/enroll`.
 */
final class Hosts
{
    public const string PREFIX = 'peh_';
    private const string PEPPER_CONTEXT = 'agent_host';
    private const int MAX_DEFAULTS = 50;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly Capabilities $capabilities,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<mixed> $defaultCapabilities the capabilities every enrolled agent asks for
     * @return array{Host, string} the host and its enrolment token, shown once
     * @throws AgentException `invalid_input`
     */
    public function create(string $ownerType, string $ownerId, ?string $organizationId, string $createdBy, mixed $name, array $defaultCapabilities): array
    {
        $name = is_string($name) ? trim($name) : '';
        if ($name === '' || mb_strlen($name) > 160) {
            throw new AgentException(AgentException::INVALID_INPUT, 'name is required, at most 160 characters.');
        }
        if (count($defaultCapabilities) > self::MAX_DEFAULTS) {
            throw new AgentException(AgentException::INVALID_INPUT, 'At most 50 default capabilities.');
        }
        foreach ($defaultCapabilities as $capability) {
            if (!is_string($capability) || $this->capabilities->find($capability) === null) {
                throw new AgentException(AgentException::CAPABILITY_NOT_FOUND, 'default_capabilities names capabilities this server declares.', null, ['invalid_capabilities' => [is_string($capability) ? $capability : '?']]);
            }
        }
        $token = self::PREFIX . Jwt::base64UrlEncode(random_bytes(32));
        $host = new Host();
        $host->id = Uuid::v7()->toRfc4122();
        $host->ownerType = $ownerType;
        $host->ownerId = $ownerId;
        $host->organizationId = $organizationId;
        $host->name = $name;
        $host->enrollmentTokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $token);
        /** @var list<string> $defaults */
        $defaults = $defaultCapabilities;
        $host->defaultCapabilities = $defaults;
        $host->createdBy = $createdBy;
        $host->createdAt = $this->clock->now();
        $this->database->insert(Schema::HOSTS, $this->row($host));

        return [$host, $token];
    }

    /**
     * The live host an enrolment token belongs to; null for a token that is not one, unknown or revoked.
     * The row is found by the keyed hash and the token re-checked in constant time.
     */
    public function authenticate(#[SensitiveParameter] string $token): ?Host
    {
        if (!str_starts_with($token, self::PREFIX)) {
            return null;
        }
        $row = $this->database->findOne(Schema::HOSTS, ['enrollment_token_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $token)]);
        if ($row === null) {
            return null;
        }
        $host = self::hydrate($row);
        if (!$this->pepper->matches(self::PEPPER_CONTEXT, $token, $host->enrollmentTokenHash) || $host->revokedAt !== null) {
            return null;
        }

        return $host;
    }

    public function find(string $id): ?Host
    {
        $row = $this->database->findOne(Schema::HOSTS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Host>
     */
    public function forOwner(string $ownerType, string $ownerId): array
    {
        $hosts = [];
        foreach ($this->database->findMany(Schema::HOSTS, ['owner_type' => $ownerType, 'owner_id' => $ownerId, 'revoked_at' => null], ['id' => 'asc']) as $row) {
            $hosts[] = self::hydrate($row);
        }

        return $hosts;
    }

    public function revoke(Host $host): void
    {
        $host->revokedAt = $this->clock->now();
        $this->database->update(Schema::HOSTS, ['id' => $host->id], ['revoked_at' => $host->revokedAt]);
    }

    /**
     * A member who leaves takes the organization's live hosts they created with them: an enrolment token
     * they hold enrols no more agents for the organization.
     *
     * @return list<Host> the hosts revoked
     */
    public function revokeForMember(string $organizationId, string $userId): array
    {
        $revoked = [];
        foreach ($this->database->findMany(Schema::HOSTS, ['owner_type' => Agent::OWNER_ORGANIZATION, 'owner_id' => $organizationId, 'created_by' => $userId, 'revoked_at' => null], ['id' => 'asc']) as $row) {
            $host = self::hydrate($row);
            $this->revoke($host);
            $revoked[] = $host;
        }

        return $revoked;
    }

    public function deleteForUser(string $userId): void
    {
        $this->database->delete(Schema::HOSTS, ['owner_type' => 'user', 'owner_id' => $userId]);
        $this->database->delete(Schema::HOSTS, ['created_by' => $userId]);
    }

    public function deleteForOrganization(string $organizationId): void
    {
        $this->database->delete(Schema::HOSTS, ['organization_id' => $organizationId]);
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Host $host): array
    {
        return [
            'id' => $host->id,
            'owner_type' => $host->ownerType,
            'owner_id' => $host->ownerId,
            'organization_id' => $host->organizationId,
            'name' => $host->name,
            'enrollment_token_hash' => $host->enrollmentTokenHash,
            'default_capabilities' => Rows::json($host->defaultCapabilities),
            'created_by' => $host->createdBy,
            'revoked_at' => $host->revokedAt,
            'created_at' => $host->createdAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Host
    {
        $host = new Host();
        $host->id = (string) $row['id'];
        $host->ownerType = (string) $row['owner_type'];
        $host->ownerId = (string) $row['owner_id'];
        $host->organizationId = Rows::nullable($row['organization_id'] ?? null);
        $host->name = (string) $row['name'];
        $host->enrollmentTokenHash = (string) $row['enrollment_token_hash'];
        $host->defaultCapabilities = Rows::strings($row['default_capabilities'] ?? null);
        $host->createdBy = (string) $row['created_by'];
        $host->revokedAt = Rows::datetime($row['revoked_at'] ?? null);
        $host->createdAt = Rows::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $host;
    }
}
