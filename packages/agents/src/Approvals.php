<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;
use Polaris\Agents\Model\Grant;
use Polaris\Config\AuthConfig;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\TokenInterface;
use Polaris\Mfa\MfaChallengeVerifier;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_map;
use function count;
use function in_array;
use function is_int;
use function mb_strlen;
use function preg_replace;
use function random_int;
use function sprintf;
use function strlen;
use function strtoupper;
use function substr;

/**
 * The approvals (`polaris_agent_approval`): one per grant request a person must decide, found by its
 * user code (the host's approval page), by the `agent.grant.requested` event (a push, CIBA) or in the
 * owner's list (`in_app`); decided once, by a session of the strength the riskiest capability needs.
 */
final class Approvals
{
    /** AAP's unambiguous alphabet: no vowels (no accidental words), no 0/O, 1/I/L. */
    public const string ALPHABET = 'BCDFGHJKMNPQRSTVWXZ';
    public const int CODE_LENGTH = 8;
    public const int POLL_INTERVAL = 5;
    /** The most approvals an agent may have waiting at once; the rest are refused until one is decided or expires. */
    public const int MAX_PENDING = 5;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Grants $grants,
        private readonly Settings $settings,
        private readonly MfaChallengeVerifier $verifier,
        private readonly AuthConfig $auth,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * An approval for pending grants, with a user code unique among the pending ones; at most
     * `MAX_PENDING` open per agent.
     *
     * @param list<Grant> $grants
     * @throws AgentException `invalid_input`, `conflict`
     */
    public function open(Agent $agent, array $grants, ?string $method, string $strength, ?string $bindingMessage): Approval
    {
        $method ??= $this->settings->approvalUrl !== null ? Approval::METHOD_DEVICE : Approval::METHOD_IN_APP;
        if (!in_array($method, Approval::METHODS, true)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'preferred_method is device_authorization, ciba or in_app.');
        }
        if ($bindingMessage !== null && mb_strlen($bindingMessage) > 160) {
            throw new AgentException(AgentException::INVALID_INPUT, 'binding_message is at most 160 characters.');
        }
        if (count($this->pendingFor([$agent])) >= self::MAX_PENDING) {
            throw new AgentException(AgentException::CONFLICT, sprintf('The agent has %d approvals waiting; one must be decided or expire first.', self::MAX_PENDING));
        }
        $now = $this->clock->now();
        $approval = new Approval();
        $approval->id = Uuid::v7()->toRfc4122();
        $approval->agentId = $agent->id;
        $approval->grantIds = array_map(static fn(Grant $grant): string => $grant->id, $grants);
        $approval->method = $method;
        $approval->strength = $strength;
        $approval->userCode = $this->freshCode();
        $approval->bindingMessage = $bindingMessage;
        $approval->status = Approval::STATUS_PENDING;
        $approval->expiresAt = $now->modify(sprintf('+%d seconds', $this->settings->approvalTtl));
        $approval->createdAt = $now;
        $approval->updatedAt = $now;
        $this->database->insert(Schema::APPROVALS, $this->row($approval));
        foreach ($grants as $grant) {
            $this->grants->attachApproval($grant, $approval->id);
        }

        return $approval;
    }

    /**
     * The decision, recorded once, in one transaction: approved grants become active (with the owner's
     * constraints when given, validated before anything is written), denied ones denied.
     *
     * @param array<string, mixed>|null $constraints
     * @return list<Grant> the grants decided
     * @throws AgentException `conflict` when the approval was already decided or expired, `invalid_input`, `unknown_constraint_operator`
     */
    public function decide(Approval $approval, bool $approve, string $decidedBy, ?array $constraints): array
    {
        $now = $this->clock->now();
        if (!$approval->isPending($now)) {
            throw new AgentException(AgentException::CONFLICT, sprintf('The approval is %s.', $approval->expiresAt <= $now ? 'expired' : $approval->status));
        }
        if ($constraints !== null) {
            Constraints::parse($constraints);
        }

        return $this->database->transaction(function () use ($approval, $approve, $decidedBy, $constraints, $now): array {
            $status = $approve ? Approval::STATUS_APPROVED : Approval::STATUS_DENIED;
            if ($this->database->update(Schema::APPROVALS, ['id' => $approval->id, 'status' => Approval::STATUS_PENDING], ['status' => $status, 'decided_by' => $decidedBy, 'updated_at' => $now]) !== 1) {
                throw new AgentException(AgentException::CONFLICT, 'The approval was already decided.');
            }
            $approval->status = $status;
            $approval->decidedBy = $decidedBy;
            $approval->updatedAt = $now;
            $decided = [];
            foreach ($approval->grantIds as $grantId) {
                $grant = $this->grants->find($grantId);
                if ($grant === null || $grant->status !== Grant::STATUS_PENDING) {
                    continue;
                }
                if ($approve) {
                    $this->grants->approve($grant, $decidedBy, $approval->method, $constraints);
                } else {
                    $this->grants->deny($grant);
                }
                $decided[] = $grant;
            }

            return $decided;
        });
    }

    /**
     * Whether the deciding session is strong enough: `session` any; `step_up` core's step-up freshness
     * (a user with a confirmed factor re-authenticated within `security.step_up.max_age`); `passkey` a
     * passkey sign-in (`amr`) with the same freshness.
     */
    public function satisfies(string $strength, TokenInterface $token): bool
    {
        $authTime = $token->getMetadata('auth_time');
        $recent = is_int($authTime) && ($this->clock->now()->getTimestamp() - $authTime) <= $this->auth->stepUpMaxAge;

        return match ($strength) {
            Settings::STRENGTH_STEP_UP => !$this->verifier->hasConfirmedFactor((string) $token->getMetadata('sub')) || $recent,
            Settings::STRENGTH_PASSKEY => in_array('passkey', (array) $token->getMetadata('amr'), true) && $recent,
            default => true,
        };
    }

    public function find(string $id): ?Approval
    {
        $row = $this->database->findOne(Schema::APPROVALS, ['id' => $id]);

        return $row === null ? null : $this->read($row);
    }

    /**
     * The pending approval behind a user code (dashes and case do not matter).
     */
    public function byUserCode(string $code): ?Approval
    {
        $code = strtoupper((string) preg_replace('/[^A-Za-z0-9]/', '', $code));
        if (strlen($code) !== self::CODE_LENGTH) {
            return null;
        }
        $row = $this->database->findOne(Schema::APPROVALS, ['user_code' => $code, 'status' => Approval::STATUS_PENDING]);
        $approval = $row === null ? null : $this->read($row);

        return $approval !== null && $approval->isPending($this->clock->now()) ? $approval : null;
    }

    /**
     * The pending approvals of the agents.
     *
     * @param list<Agent> $agents
     * @return list<Approval>
     */
    public function pendingFor(array $agents): array
    {
        $now = $this->clock->now();
        $pending = [];
        foreach ($agents as $agent) {
            foreach ($this->database->findMany(Schema::APPROVALS, ['agent_id' => $agent->id, 'status' => Approval::STATUS_PENDING], ['id' => 'asc']) as $row) {
                $approval = $this->read($row);
                if ($approval->isPending($now)) {
                    $pending[] = $approval;
                }
            }
        }

        return $pending;
    }

    public function cancelPending(Agent $agent): int
    {
        return $this->database->update(Schema::APPROVALS, ['agent_id' => $agent->id, 'status' => Approval::STATUS_PENDING], ['status' => Approval::STATUS_CANCELLED, 'updated_at' => $this->clock->now()]);
    }

    public function deleteForAgent(Agent $agent): void
    {
        $this->database->delete(Schema::APPROVALS, ['agent_id' => $agent->id]);
    }

    /**
     * `XXXX-XXXX`, as a person reads it.
     */
    public static function display(string $code): string
    {
        return substr($code, 0, 4) . '-' . substr($code, 4);
    }

    /**
     * A code no pending approval holds (2.6e10 of space; a collision is retried).
     */
    private function freshCode(): string
    {
        $alphabet = self::ALPHABET;
        for ($attempt = 0; $attempt < 10; ++$attempt) {
            $code = '';
            for ($i = 0; $i < self::CODE_LENGTH; ++$i) {
                $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
            }
            if ($this->database->findOne(Schema::APPROVALS, ['user_code' => $code, 'status' => Approval::STATUS_PENDING]) === null) {
                return $code;
            }
        }
        throw new AgentException(AgentException::CONFLICT, 'No user code is free right now; try again.');
    }

    /**
     * A row as it reads now: a pending approval past its expiry reads `expired` (nothing is written; the
     * kill switch's cancellation and the pending lookups still see the stored status).
     *
     * @param array<string, mixed> $row
     */
    private function read(array $row): Approval
    {
        $approval = self::hydrate($row);
        if ($approval->status === Approval::STATUS_PENDING && $approval->expiresAt <= $this->clock->now()) {
            $approval->status = Approval::STATUS_EXPIRED;
        }

        return $approval;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Approval $approval): array
    {
        return [
            'id' => $approval->id,
            'agent_id' => $approval->agentId,
            'grant_ids' => Rows::json($approval->grantIds),
            'method' => $approval->method,
            'strength' => $approval->strength,
            'user_code' => $approval->userCode,
            'binding_message' => $approval->bindingMessage,
            'status' => $approval->status,
            'decided_by' => $approval->decidedBy,
            'expires_at' => $approval->expiresAt,
            'created_at' => $approval->createdAt,
            'updated_at' => $approval->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Approval
    {
        $approval = new Approval();
        $approval->id = (string) $row['id'];
        $approval->agentId = (string) $row['agent_id'];
        $approval->grantIds = Rows::strings($row['grant_ids'] ?? null);
        $approval->method = (string) $row['method'];
        $approval->strength = (string) $row['strength'];
        $approval->userCode = (string) $row['user_code'];
        $approval->bindingMessage = Rows::nullable($row['binding_message'] ?? null);
        $approval->status = (string) $row['status'];
        $approval->decidedBy = Rows::nullable($row['decided_by'] ?? null);
        $approval->expiresAt = Rows::datetime($row['expires_at']) ?? new DateTimeImmutable();
        $approval->createdAt = Rows::datetime($row['created_at']) ?? new DateTimeImmutable();
        $approval->updatedAt = Rows::datetime($row['updated_at']) ?? $approval->createdAt;

        return $approval;
    }
}
