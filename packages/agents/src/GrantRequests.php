<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;
use Polaris\Agents\Model\Grant;
use Polaris\Contract\DatabaseAdapter;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_map;
use function array_search;
use function max;

/**
 * A grant request end to end (`POST /agents/grants/request`, the capabilities asked at registration
 * and the host's defaults at enrolment): the grants, the auto-approvals, one approval for what a person
 * must decide (of the strength the riskiest capability needs), and the events.
 */
final class GrantRequests
{
    public function __construct(
        private readonly Grants $grants,
        private readonly Approvals $approvals,
        private readonly Capabilities $capabilities,
        private readonly Settings $settings,
        private readonly DatabaseAdapter $database,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param list<mixed> $asked capability names, or `{name, constraints}`
     * @return array{grants: list<Grant>, approval: Approval|null}
     * @throws AgentException
     */
    public function request(Agent $agent, array $asked, ?string $method, ?string $bindingMessage, ?string $reason, bool $byAgent, ?string $ip = null, ?string $userAgent = null): array
    {
        // The grants and their approval in one transaction: a refused approval (too many waiting) writes no grant.
        [$result, $approval] = $this->database->transaction(function () use ($agent, $asked, $method, $bindingMessage): array {
            $result = $this->grants->request($agent, $asked);
            $pending = $result['pending'];
            $approval = null;
            // A grant already waiting keeps its approval while that one is open; one whose approval expired joins a new one.
            foreach ($result['reused'] as $grant) {
                $open = $grant->approvalId === null ? null : $this->approvals->find($grant->approvalId);
                if ($open !== null && $open->status === Approval::STATUS_PENDING) {
                    $approval ??= $open;
                } else {
                    $pending[] = $grant;
                }
            }
            if ($pending !== []) {
                $approval = $this->approvals->open($agent, $pending, $method, $this->strengthFor($pending), $bindingMessage);
            }

            return [$result, $approval];
        });
        $data = ['capabilities' => array_map(static fn(Grant $grant): string => $grant->capability, $result['grants']), 'reason' => $reason, 'approval_id' => $approval?->id, 'method' => $approval?->method, 'user_code' => $approval?->userCode, 'binding_message' => $bindingMessage];
        $this->events->dispatch($byAgent
            ? AgentEvent::byAgent(AuditNames::GRANT_REQUESTED, $agent->id, $agent->subject(), $agent->organizationId, $data, $ip, $userAgent)
            : AgentEvent::byUser(AuditNames::GRANT_REQUESTED, $agent->id, $agent->subject(), $agent->organizationId, $data, $ip, $userAgent));
        foreach ($result['approved'] as $grant) {
            $this->events->dispatch(AgentEvent::bySystem(AuditNames::GRANT_APPROVED, $agent->id, $agent->subject(), $agent->organizationId, ['capability' => $grant->capability, 'grant_id' => $grant->id, 'how' => Grant::VIA_AUTO, 'budget' => $grant->budgetTotal]));
        }

        return ['grants' => $result['grants'], 'approval' => $approval];
    }

    /**
     * The AAP response: the agent, its grants, and the approval when a person must decide.
     *
     * @param list<Grant> $grants
     * @return array<string, mixed>
     */
    public function response(Agent $agent, array $grants, ?Approval $approval): array
    {
        $body = ['agent_id' => $agent->id, 'agent_capability_grants' => array_map(static fn(Grant $grant): array => $grant->toArray(), $grants)];
        if ($approval !== null) {
            $body['approval'] = $this->approvalResponse($approval);
        }

        return $body;
    }

    /**
     * @return array<string, mixed>
     */
    public function approvalResponse(Approval $approval): array
    {
        $code = Approvals::display($approval->userCode);
        // Without the host's device page, the data route the page would read (`GET /agents/approvals/code`).
        $uri = $this->settings->approvalUrl ?? $this->settings->url('/agents/approvals/code');

        return [
            'id' => $approval->id,
            'method' => $approval->method,
            'strength' => $approval->strength,
            'user_code' => $code,
            'verification_uri' => $uri,
            'verification_uri_complete' => $uri . '?user_code=' . $code,
            'expires_in' => $this->settings->approvalTtl,
            'interval' => Approvals::POLL_INTERVAL,
            'binding_message' => $approval->bindingMessage,
        ];
    }

    /**
     * What the owner sees of a pending approval: the approval, how to reach it, the agent and the grants.
     *
     * @return array<string, mixed>
     */
    public function describe(Approval $approval, ?Agent $agent): array
    {
        $grants = [];
        foreach ($approval->grantIds as $grantId) {
            $grant = $this->grants->find($grantId);
            if ($grant !== null) {
                $grants[] = $grant->toArray();
            }
        }

        return [...$approval->toArray(), ...$this->approvalResponse($approval), 'agent' => $agent?->toArray(), 'grants' => $grants];
    }

    /**
     * The strongest of the strengths the capabilities' risks require.
     *
     * @param list<Grant> $grants
     */
    private function strengthFor(array $grants): string
    {
        $rank = 0;
        foreach ($grants as $grant) {
            $capability = $this->capabilities->find($grant->capability);
            $strength = $this->settings->strengthFor($capability === null ? Settings::RISK_HIGH : $capability->risk);
            $position = array_search($strength, Settings::STRENGTHS, true);
            $rank = max($rank, $position === false ? 0 : $position);
        }

        return Settings::STRENGTHS[$rank];
    }
}
