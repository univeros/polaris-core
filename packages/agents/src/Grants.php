<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Grant;
use Polaris\Authorization\PermissionResolver;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Increment;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Model\Client;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_unique;
use function array_values;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

/**
 * The capability grants (`polaris_agent_grant`): asked by an agent, approved by its owner or by the
 * auto-approval policy, spent by a conditional update in the execution's transaction, revoked by the
 * owner or the kill switch. The agent's OAuth client scopes follow its live grants.
 */
final class Grants
{
    private const int MAX_PER_REQUEST = 20;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Capabilities $capabilities,
        private readonly Settings $settings,
        private readonly PermissionResolver $permissions,
        private readonly Clients $clients,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The grants an agent asks for: one per capability named (`name` or `{name, constraints}`), active at
     * once when the policy auto-approves the risk tier within its budget and the owner holds the
     * permission, pending otherwise; a capability the agent already holds live, or already waits for, is
     * answered as it is (`reused`: the pending ones, so the caller re-attaches an approval when theirs
     * expired, and an agent asking again never piles up approvals).
     *
     * @param list<mixed> $asked
     * @return array{grants: list<Grant>, pending: list<Grant>, approved: list<Grant>, reused: list<Grant>}
     * @throws AgentException `capability_not_found`, `unknown_constraint_operator`, `invalid_input`
     */
    public function request(Agent $agent, array $asked): array
    {
        if ($asked === [] || count($asked) > self::MAX_PER_REQUEST) {
            throw new AgentException(AgentException::INVALID_INPUT, sprintf('capabilities names 1 to %d capabilities.', self::MAX_PER_REQUEST));
        }
        $now = $this->clock->now();
        $result = ['grants' => [], 'pending' => [], 'approved' => [], 'reused' => []];
        $seen = [];
        foreach ($asked as $item) {
            $name = is_string($item) ? $item : (is_array($item) && is_string($item['name'] ?? null) ? $item['name'] : '');
            $capability = $this->capabilities->find($name);
            if ($capability === null) {
                throw new AgentException(AgentException::CAPABILITY_NOT_FOUND, sprintf('Unknown capability "%s".', $name), null, ['invalid_capabilities' => [$name]]);
            }
            if (isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $existing = $this->activeFor($agent, $name) ?? $this->pendingFor($agent, $name);
            if ($existing !== null) {
                $result['grants'][] = $existing;
                if ($existing->status === Grant::STATUS_PENDING) {
                    $result['reused'][] = $existing;
                }
                continue;
            }
            $raw = is_array($item) && is_array($item['constraints'] ?? null) ? $item['constraints'] : [];
            $parsed = Constraints::parse($raw);
            $grant = new Grant();
            $grant->id = Uuid::v7()->toRfc4122();
            $grant->agentId = $agent->id;
            $grant->capability = $name;
            $grant->constraints = $parsed['fields'];
            $grant->createdAt = $now;
            $grant->updatedAt = $now;
            $this->budget($grant, $parsed['budget']);
            $auto = $this->settings->autoApprove[$capability->risk] ?? null;
            if ($auto !== null && self::withinPolicy($parsed['budget'], $auto) && $this->ownerHolds($agent, $capability->permission)) {
                if ($grant->budgetKind === null && is_array($auto)) {
                    $this->budget($grant, Constraints::budget($auto));
                }
                $grant->status = Grant::STATUS_ACTIVE;
                $grant->approvedVia = Grant::VIA_AUTO;
                $result['approved'][] = $grant;
            } else {
                $result['pending'][] = $grant;
            }
            $this->database->insert(Schema::GRANTS, $this->row($grant));
            $result['grants'][] = $grant;
        }
        if ($result['approved'] !== []) {
            $this->syncClientScopes($agent);
        }

        return $result;
    }

    /**
     * A pending grant approved by a person: once only, with the constraints they may have narrowed.
     *
     * @param array<string, mixed>|null $constraints the owner's constraints, replacing the asked ones
     * @throws AgentException `conflict`
     */
    public function approve(Grant $grant, string $by, string $via, ?array $constraints = null): void
    {
        $now = $this->clock->now();
        if ($constraints !== null) {
            $parsed = Constraints::parse($constraints);
            $grant->constraints = $parsed['fields'];
            $this->budget($grant, $parsed['budget']);
        }
        $grant->status = Grant::STATUS_ACTIVE;
        $grant->grantedBy = $by;
        $grant->approvedVia = $via;
        $grant->updatedAt = $now;
        if ($this->database->update(Schema::GRANTS, ['id' => $grant->id, 'status' => Grant::STATUS_PENDING], $this->row($grant)) !== 1) {
            throw new AgentException(AgentException::CONFLICT, 'The grant is no longer pending.');
        }
    }

    /**
     * The approval a pending grant waits for.
     */
    public function attachApproval(Grant $grant, string $approvalId): void
    {
        $grant->approvalId = $approvalId;
        $this->database->update(Schema::GRANTS, ['id' => $grant->id], ['approval_id' => $approvalId]);
    }

    public function deny(Grant $grant): void
    {
        $this->end($grant, Grant::STATUS_PENDING, Grant::STATUS_DENIED);
    }

    /**
     * @throws AgentException `conflict` when the grant is not live
     */
    public function revoke(Grant $grant): void
    {
        $this->end($grant, [Grant::STATUS_ACTIVE, Grant::STATUS_PENDING], Grant::STATUS_REVOKED);
    }

    /**
     * Every live or pending grant of the agent revoked (the kill switch); the client's scopes are synced
     * by the caller's transaction end.
     */
    public function revokeAll(Agent $agent): int
    {
        $now = $this->clock->now();

        return $this->database->update(Schema::GRANTS, ['agent_id' => $agent->id, 'status' => [Grant::STATUS_ACTIVE, Grant::STATUS_PENDING]], ['status' => Grant::STATUS_REVOKED, 'updated_at' => $now]);
    }

    /**
     * Spends `$cost` of the grant's budget by a conditional update: the remaining budget after, or null
     * when the grant had less than the cost (nothing was spent). A grant without a budget costs nothing.
     */
    public function spend(Grant $grant, int $cost): ?int
    {
        if ($grant->budgetKind === null) {
            return null;
        }
        $updated = $this->database->update(
            Schema::GRANTS,
            ['id' => $grant->id, 'status' => Grant::STATUS_ACTIVE, 'budget_remaining' => Condition::gte($cost)],
            ['budget_remaining' => new Increment(-$cost), 'updated_at' => $this->clock->now()],
        );
        if ($updated !== 1) {
            return null;
        }
        $grant->budgetRemaining = (int) $grant->budgetRemaining - $cost;

        return $grant->budgetRemaining;
    }

    /**
     * A grant whose budget reached zero.
     */
    public function exhaust(Grant $grant): void
    {
        $this->end($grant, Grant::STATUS_ACTIVE, Grant::STATUS_EXHAUSTED);
    }

    public function find(string $id): ?Grant
    {
        $row = $this->database->findOne(Schema::GRANTS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * The live grant of the agent for a capability, if any.
     */
    public function activeFor(Agent $agent, string $capability): ?Grant
    {
        foreach ($this->forAgent($agent, Grant::STATUS_ACTIVE) as $grant) {
            if ($grant->capability === $capability && $grant->isLive($this->clock->now())) {
                return $grant;
            }
        }

        return null;
    }

    /**
     * The grant of the agent for a capability still waiting for a decision, if any.
     */
    public function pendingFor(Agent $agent, string $capability): ?Grant
    {
        foreach ($this->forAgent($agent, Grant::STATUS_PENDING) as $grant) {
            if ($grant->capability === $capability) {
                return $grant;
            }
        }

        return null;
    }

    /**
     * @return list<Grant>
     */
    public function forAgent(Agent $agent, ?string $status = null): array
    {
        $criteria = ['agent_id' => $agent->id];
        if ($status !== null) {
            $criteria['status'] = $status;
        }
        $grants = [];
        foreach ($this->database->findMany(Schema::GRANTS, $criteria, ['id' => 'asc']) as $row) {
            $grants[] = self::hydrate($row);
        }

        return $grants;
    }

    /**
     * @return list<Grant>
     */
    public function live(Agent $agent): array
    {
        $now = $this->clock->now();

        return array_values(array_filter($this->forAgent($agent, Grant::STATUS_ACTIVE), static fn(Grant $grant): bool => $grant->isLive($now)));
    }

    /**
     * The permissions the agent's live grants require: what its tokens may carry.
     *
     * @return list<string>
     */
    public function permissionsOf(Agent $agent): array
    {
        $permissions = [];
        foreach ($this->live($agent) as $grant) {
            $capability = $this->capabilities->find($grant->capability);
            if ($capability !== null) {
                $permissions[] = $capability->permission;
            }
        }

        return array_values(array_unique($permissions));
    }

    /**
     * Whether the agent's owner (the user it acts as, in its organization) holds the permission now.
     */
    public function ownerHolds(Agent $agent, string $permission): bool
    {
        return in_array($permission, $this->permissions->resolve($agent->subject(), $agent->organizationId)->scope, true);
    }

    /**
     * The agent's OAuth client may only ask for the scopes its live grants require.
     */
    public function syncClientScopes(Agent $agent): void
    {
        $client = $this->clients->find($agent->id);
        if (!$client instanceof Client || $client->disabledAt !== null) {
            return;
        }
        $scopes = $this->permissionsOf($agent);
        $this->clients->update($client, ['scopes' => $scopes === [] ? [Agents::NO_GRANT_SCOPE] : $scopes], false);
    }

    public function deleteForAgent(Agent $agent): void
    {
        $this->database->delete(Schema::GRANTS, ['agent_id' => $agent->id]);
    }

    /**
     * Whether the policy approves the asked budget: none asked (the policy's applies), or the same kind
     * and field, no larger, and no longer a window than the policy's when it has one. The policy's budget
     * is a ceiling the asker cannot raise; anything wider waits for a person.
     *
     * @param array{kind: string, total: int, field: string|null, window: int|null}|null $asked
     * @param array<string, mixed>|true $policy
     */
    private static function withinPolicy(?array $asked, array|true $policy): bool
    {
        if ($asked === null || $policy === true) {
            return true;
        }
        $ceiling = Constraints::budget($policy);
        if ($asked['kind'] !== $ceiling['kind'] || $asked['field'] !== $ceiling['field'] || $asked['total'] > $ceiling['total']) {
            return false;
        }

        return $ceiling['window'] === null || ($asked['window'] !== null && $asked['window'] <= $ceiling['window']);
    }

    /**
     * @param array{kind: string, total: int, field: string|null, window: int|null}|null $budget
     */
    private function budget(Grant $grant, ?array $budget): void
    {
        $grant->budgetKind = $budget['kind'] ?? null;
        $grant->budgetTotal = $budget['total'] ?? null;
        $grant->budgetRemaining = $budget['total'] ?? null;
        $grant->budgetField = $budget['field'] ?? null;
        // The window, when set, is the grant's lifetime from its creation (decisions, WP4).
        $grant->expiresAt = isset($budget['window']) ? $grant->createdAt->modify(sprintf('+%d seconds', $budget['window'])) : null;
    }

    /**
     * @param string|list<string> $from
     */
    private function end(Grant $grant, string|array $from, string $to): void
    {
        $now = $this->clock->now();
        if ($this->database->update(Schema::GRANTS, ['id' => $grant->id, 'status' => $from], ['status' => $to, 'updated_at' => $now]) !== 1) {
            throw new AgentException(AgentException::CONFLICT, sprintf('The grant is %s and cannot be %s.', $grant->status, $to));
        }
        $grant->status = $to;
        $grant->updatedAt = $now;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Grant $grant): array
    {
        return [
            'id' => $grant->id,
            'agent_id' => $grant->agentId,
            'capability' => $grant->capability,
            'constraints' => Rows::json((object) $grant->constraints),
            'budget_total' => $grant->budgetTotal,
            'budget_remaining' => $grant->budgetRemaining,
            'budget_kind' => $grant->budgetKind,
            'budget_field' => $grant->budgetField,
            'status' => $grant->status,
            'granted_by' => $grant->grantedBy,
            'approved_via' => $grant->approvedVia,
            'approval_id' => $grant->approvalId,
            'expires_at' => $grant->expiresAt,
            'created_at' => $grant->createdAt,
            'updated_at' => $grant->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Grant
    {
        $grant = new Grant();
        $grant->id = (string) $row['id'];
        $grant->agentId = (string) $row['agent_id'];
        $grant->capability = (string) $row['capability'];
        $constraints = [];
        foreach (Rows::array($row['constraints'] ?? null) ?? [] as $field => $operators) {
            if (is_string($field) && is_array($operators)) {
                $constraints[$field] = $operators;
            }
        }
        $grant->constraints = $constraints;
        $grant->budgetTotal = Rows::int($row['budget_total'] ?? null);
        $grant->budgetRemaining = Rows::int($row['budget_remaining'] ?? null);
        $grant->budgetKind = Rows::nullable($row['budget_kind'] ?? null);
        $grant->budgetField = Rows::nullable($row['budget_field'] ?? null);
        $grant->status = (string) $row['status'];
        $grant->grantedBy = Rows::nullable($row['granted_by'] ?? null);
        $grant->approvedVia = Rows::nullable($row['approved_via'] ?? null);
        $grant->approvalId = Rows::nullable($row['approval_id'] ?? null);
        $grant->expiresAt = Rows::datetime($row['expires_at'] ?? null);
        $grant->createdAt = Rows::datetime($row['created_at']) ?? new DateTimeImmutable();
        $grant->updatedAt = Rows::datetime($row['updated_at']) ?? $grant->createdAt;

        return $grant;
    }
}
