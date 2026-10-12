<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Receipt;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;
use Polaris\OAuth\Tokens;
use Psr\Clock\ClockInterface;

use function in_array;
use function is_array;
use function is_string;
use function mb_strlen;
use function trim;

/**
 * The agents (`polaris_agent`): each is an OAuth client of polaris/oauth-provider created through
 * `Clients::create`, and the agent's id is the client's `client_id`, so a client-credentials token's
 * `sub` is the agent and an exchanged token's `act.sub` names it. The client's grant types follow the
 * mode (autonomous: `client_credentials`; delegated: the token exchange) and its scopes follow the
 * agent's active grants ({@see Grants::syncClientScopes()}). The client belongs to no organization:
 * the plugin manages it (the kill switch, the scopes, erasure), so the organization's self-service
 * client routes never list, rewrite or delete it; the agent row carries the organization.
 */
final class Agents
{
    /**
     * The provider reads an empty scope list as "any scope the server knows", so an agent without an
     * active grant gets the harmless `profile` scope: it can mint a scopeless token (to ask for grants,
     * read its session) and nothing else.
     */
    public const string NO_GRANT_SCOPE = Scopes::PROFILE;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Clients $clients,
        private readonly Tokens $tokens,
        private readonly Grants $grants,
        private readonly Approvals $approvals,
        private readonly Receipts $receipts,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Registers the agent and its OAuth client.
     *
     * @param array<string, mixed> $fields `name`, `mode`, `auth`, `jwk` (the public JWK, for `private_key_jwt`)
     * @return array{Agent, string|null} the agent and, for `client_secret`, the secret shown once
     * @throws AgentException `invalid_input`
     */
    public function create(array $fields, string $ownerType, string $ownerId, ?string $organizationId, string $createdBy, ?string $hostId): array
    {
        $name = is_string($fields['name'] ?? null) ? trim($fields['name']) : '';
        $mode = $fields['mode'] ?? Agent::MODE_DELEGATED;
        $auth = $fields['auth'] ?? Agent::AUTH_PRIVATE_KEY_JWT;
        if ($name === '' || mb_strlen($name) > 160) {
            throw new AgentException(AgentException::INVALID_INPUT, 'name is required, at most 160 characters.');
        }
        if (!is_string($mode) || !in_array($mode, Agent::MODES, true)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'mode is delegated or autonomous.');
        }
        if (!is_string($auth) || !in_array($auth, Agent::AUTHS, true)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'auth is private_key_jwt, client_secret or delegated_token.');
        }
        if ($auth === Agent::AUTH_DELEGATED_TOKEN && $mode !== Agent::MODE_DELEGATED) {
            throw new AgentException(AgentException::INVALID_INPUT, 'delegated_token authenticates a delegated agent only: an autonomous agent needs a key or a secret.');
        }
        $jwk = null;
        if ($auth === Agent::AUTH_PRIVATE_KEY_JWT) {
            $jwk = AgentKeys::publicJwk($fields['jwk'] ?? null);
        }
        $now = $this->clock->now();
        $agent = new Agent();
        $agent->ownerType = $ownerType;
        $agent->ownerId = $ownerId;
        $agent->organizationId = $organizationId;
        $agent->name = $name;
        $agent->mode = $mode;
        $agent->hostId = $hostId;
        $agent->auth = $auth;
        $agent->publicJwk = $jwk;
        $agent->status = Agent::STATUS_ACTIVE;
        $agent->createdBy = $createdBy;
        $agent->createdAt = $now;
        $agent->updatedAt = $now;
        try {
            $issued = $this->clients->create(self::clientFields($agent), null, $createdBy, false);
        } catch (OAuthException $exception) {
            throw new AgentException(AgentException::INVALID_INPUT, 'The agent\'s OAuth client could not be registered: ' . $exception->description);
        }
        $agent->id = $issued->client->clientId;
        $this->database->insert(Schema::AGENTS, $this->row($agent));

        return [$agent, $issued->secret];
    }

    public function find(string $id): ?Agent
    {
        if ($id === '') {
            return null;
        }
        $row = $this->database->findOne(Schema::AGENTS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Agent>
     */
    public function forOwner(string $ownerType, string $ownerId): array
    {
        return $this->list(['owner_type' => $ownerType, 'owner_id' => $ownerId]);
    }

    /**
     * @return list<Agent>
     */
    public function all(): array
    {
        return $this->list([]);
    }

    public function client(Agent $agent): ?Client
    {
        return $this->clients->find($agent->id);
    }

    /**
     * @throws AgentException `conflict` when the agent is not active
     */
    public function suspend(Agent $agent): void
    {
        $this->transition($agent, Agent::STATUS_ACTIVE, Agent::STATUS_SUSPENDED, 'Only an active agent can be suspended.');
    }

    /**
     * @throws AgentException `conflict` when the agent is not suspended
     */
    public function resume(Agent $agent): void
    {
        $this->transition($agent, Agent::STATUS_SUSPENDED, Agent::STATUS_ACTIVE, 'Only a suspended agent can be resumed.');
    }

    /**
     * The kill switch: the agent is revoked, its OAuth client disabled and every token of it revoked, its
     * grants revoked, its pending approvals cancelled, and its receipt chain sealed with a final
     * receipt, all in one transaction.
     *
     * @return array{Receipt, int} the sealing receipt and the number of grants revoked
     * @throws AgentException `conflict` when the agent was already revoked
     */
    public function revoke(Agent $agent): array
    {
        return $this->database->transaction(function () use ($agent): array {
            $now = $this->clock->now();
            if ($this->database->update(Schema::AGENTS, ['id' => $agent->id, 'status' => [Agent::STATUS_ACTIVE, Agent::STATUS_SUSPENDED]], ['status' => Agent::STATUS_REVOKED, 'sealed_at' => $now, 'updated_at' => $now]) !== 1) {
                throw new AgentException(AgentException::CONFLICT, 'The agent is already revoked.');
            }
            $agent->status = Agent::STATUS_REVOKED;
            $agent->sealedAt = $now;
            $agent->updatedAt = $now;
            $client = $this->clients->find($agent->id);
            if ($client instanceof Client) {
                $this->clients->update($client, ['disabled' => true], false);
            }
            $this->tokens->revokeForClient($agent->id);
            $revoked = $this->grants->revokeAll($agent);
            $this->approvals->cancelPending($agent);

            return [$this->receipts->seal($agent), $revoked];
        });
    }

    public function deleteForUser(string $userId): void
    {
        foreach ([...$this->forOwner(Agent::OWNER_USER, $userId), ...$this->list(['created_by' => $userId])] as $agent) {
            $this->erase($agent);
        }
    }

    public function deleteForOrganization(string $organizationId): void
    {
        foreach ($this->list(['organization_id' => $organizationId]) as $agent) {
            $this->erase($agent);
        }
    }

    /**
     * A member who leaves takes the organization's agents they registered with them.
     *
     * @return list<Agent> the agents revoked
     */
    public function revokeForMember(string $organizationId, string $userId): array
    {
        $revoked = [];
        foreach ($this->list(['owner_type' => Agent::OWNER_ORGANIZATION, 'owner_id' => $organizationId, 'created_by' => $userId]) as $agent) {
            if ($agent->status !== Agent::STATUS_REVOKED) {
                $this->revoke($agent);
                $revoked[] = $agent;
            }
        }

        return $revoked;
    }

    /**
     * The registration of the agent's OAuth client: the mode decides the grant, `auth` the method.
     *
     * @return array<string, mixed>
     */
    private static function clientFields(Agent $agent): array
    {
        $public = $agent->auth === Agent::AUTH_DELEGATED_TOKEN;

        return [
            'name' => $agent->name,
            'type' => $public ? Client::TYPE_PUBLIC : Client::TYPE_CONFIDENTIAL,
            'grant_types' => [$agent->mode === Agent::MODE_AUTONOMOUS ? Clients::GRANT_CLIENT : Clients::GRANT_EXCHANGE],
            'token_endpoint_auth_method' => match ($agent->auth) {
                Agent::AUTH_PRIVATE_KEY_JWT => Client::AUTH_PRIVATE_KEY_JWT,
                Agent::AUTH_CLIENT_SECRET => Client::AUTH_SECRET_BASIC,
                default => Client::AUTH_NONE,
            },
            'jwks' => $agent->publicJwk === null ? null : ['keys' => [$agent->publicJwk]],
            'scopes' => [self::NO_GRANT_SCOPE],
        ];
    }

    private function transition(Agent $agent, string $from, string $to, string $otherwise): void
    {
        $now = $this->clock->now();
        if ($this->database->update(Schema::AGENTS, ['id' => $agent->id, 'status' => $from], ['status' => $to, 'updated_at' => $now]) !== 1) {
            throw new AgentException(AgentException::CONFLICT, $otherwise);
        }
        $agent->status = $to;
        $agent->updatedAt = $now;
    }

    /**
     * An erased owner leaves nothing behind: the client and its tokens, the grants, approvals and receipts.
     */
    private function erase(Agent $agent): void
    {
        $this->tokens->deleteForClient($agent->id);
        $client = $this->clients->find($agent->id);
        if ($client instanceof Client) {
            $this->clients->delete($client);
        }
        $this->grants->deleteForAgent($agent);
        $this->approvals->deleteForAgent($agent);
        $this->receipts->deleteForAgent($agent);
        $this->database->delete(Schema::AGENTS, ['id' => $agent->id]);
    }

    /**
     * @param array<string, mixed> $criteria
     * @return list<Agent>
     */
    private function list(array $criteria): array
    {
        $agents = [];
        foreach ($this->database->findMany(Schema::AGENTS, $criteria, ['id' => 'asc']) as $row) {
            $agents[] = self::hydrate($row);
        }

        return $agents;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Agent $agent): array
    {
        return [
            'id' => $agent->id,
            'owner_type' => $agent->ownerType,
            'owner_id' => $agent->ownerId,
            'organization_id' => $agent->organizationId,
            'name' => $agent->name,
            'mode' => $agent->mode,
            'host_id' => $agent->hostId,
            'auth' => $agent->auth,
            'public_jwk' => $agent->publicJwk === null ? null : Rows::json($agent->publicJwk),
            'status' => $agent->status,
            'created_by' => $agent->createdBy,
            'sealed_at' => $agent->sealedAt,
            'created_at' => $agent->createdAt,
            'updated_at' => $agent->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Agent
    {
        $agent = new Agent();
        $agent->id = (string) $row['id'];
        $agent->ownerType = (string) $row['owner_type'];
        $agent->ownerId = (string) $row['owner_id'];
        $agent->organizationId = Rows::nullable($row['organization_id'] ?? null);
        $agent->name = (string) $row['name'];
        $agent->mode = (string) $row['mode'];
        $agent->hostId = Rows::nullable($row['host_id'] ?? null);
        $agent->auth = (string) $row['auth'];
        $jwk = Rows::array($row['public_jwk'] ?? null);
        /** @var array<string, mixed>|null $jwk */
        $agent->publicJwk = is_array($jwk) ? $jwk : null;
        $agent->status = (string) $row['status'];
        $agent->createdBy = (string) $row['created_by'];
        $agent->sealedAt = Rows::datetime($row['sealed_at'] ?? null);
        $agent->createdAt = Rows::datetime($row['created_at']) ?? new DateTimeImmutable();
        $agent->updatedAt = Rows::datetime($row['updated_at']) ?? $agent->createdAt;

        return $agent;
    }
}
