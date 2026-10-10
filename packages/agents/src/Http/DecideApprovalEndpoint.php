<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\Approvals;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Capabilities;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Grants;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;
use Polaris\Agents\Model\Grant;
use Polaris\Authorization\Gate;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_map;
use function in_array;
use function is_array;
use function sprintf;

/**
 * `POST /agents/approvals/{id}/decide`: the owner approves or denies, once. Approving needs a session
 * of the strength the approval asks (`session`, `step_up`: core's step-up freshness, `passkey`: a recent
 * passkey sign-in) and the owner must hold every capability's permission now; `constraints` narrows
 * what was asked.
 */
final class DecideApprovalEndpoint extends AgentsEndpoint
{
    public function __construct(
        private readonly Approvals $approvals,
        private readonly Agents $agents,
        private readonly Grants $grants,
        private readonly Capabilities $capabilities,
        private readonly Gate $gate,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $decision = $input->get('decision');
        $constraints = $input->get('constraints');
        if (!in_array($decision, ['approve', 'deny'], true) || ($constraints !== null && !is_array($constraints))) {
            return $this->refuse(new AgentException(AgentException::INVALID_INPUT, 'decision is approve or deny; constraints, when given, an object.'));
        }
        $approval = $this->approvals->find((string) $input->get('id'));
        $agent = $approval === null ? null : $this->agents->find($approval->agentId);
        if ($approval === null || $agent === null || !$this->manages($agent, $token, $this->gate)) {
            return $this->refuse(new AgentException(AgentException::NOT_FOUND, 'The approval does not exist.'));
        }
        $approve = $decision === 'approve';
        try {
            if ($approve) {
                $this->assertMayApprove($approval, $agent, $token);
            }
            $decided = $this->approvals->decide($approval, $approve, $this->actorId($token), $constraints);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }
        $this->grants->syncClientScopes($agent);
        $context = $this->client($input);
        foreach ($decided as $grant) {
            $this->events->dispatch(AgentEvent::byUser($approve ? AuditNames::GRANT_APPROVED : AuditNames::GRANT_DENIED, $agent->id, $this->actorId($token), $agent->organizationId, ['capability' => $grant->capability, 'grant_id' => $grant->id, 'how' => $approval->method, 'budget' => $grant->budgetTotal], $context->ip, $context->userAgent));
        }

        return $this->respond(200, ['data' => [...$approval->toArray(), 'grants' => array_map(static fn(Grant $grant): array => $grant->toArray(), $decided)]]);
    }

    /**
     * @throws AgentException `step_up_required`, `permission_not_held`
     */
    private function assertMayApprove(Approval $approval, Agent $agent, TokenInterface $token): void
    {
        if (!$this->approvals->satisfies($approval->strength, $token)) {
            throw new AgentException(AgentException::STEP_UP_REQUIRED, sprintf('Approving needs a session of strength "%s".', $approval->strength), null, ['strength' => $approval->strength]);
        }
        foreach ($approval->grantIds as $grantId) {
            $grant = $this->grants->find($grantId);
            $capability = $grant === null ? null : $this->capabilities->find($grant->capability);
            if ($capability === null) {
                continue;
            }
            $holds = $agent->ownerType === Agent::OWNER_USER
                ? $this->grants->ownerHolds($agent, $capability->permission)
                : $this->gate->allows($token, $capability->permission);
            if (!$holds) {
                throw new AgentException(AgentException::PERMISSION_NOT_HELD, sprintf('The permission "%s" the capability "%s" requires is not held.', $capability->permission, $capability->name));
            }
        }
    }
}
