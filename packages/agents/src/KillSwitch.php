<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Receipt;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The kill switch as the owner, an operator or a listener pulls it: {@see Agents::revoke()} and the
 * `agent.revoked` and `agent.receipt.sealed` events.
 */
final class KillSwitch
{
    public function __construct(private readonly Agents $agents, private readonly EventDispatcherInterface $events)
    {
    }

    /**
     * @param string|null $byUserId the person revoking; null for the system or an operator key
     * @throws AgentException `conflict` when the agent was already revoked
     */
    public function revoke(Agent $agent, ?string $byUserId, string $how, ?string $ip = null, ?string $userAgent = null): Receipt
    {
        [$receipt, $grants] = $this->agents->revoke($agent);
        $data = ['name' => $agent->name, 'how' => $how, 'grants_revoked' => $grants, 'sealed_receipt_id' => $receipt->id];
        $this->events->dispatch($byUserId === null
            ? AgentEvent::bySystem(AuditNames::REVOKED, $agent->id, $agent->subject(), $agent->organizationId, $data)
            : AgentEvent::byUser(AuditNames::REVOKED, $agent->id, $byUserId, $agent->organizationId, $data, $ip, $userAgent));
        $this->events->dispatch(AgentEvent::bySystem(AuditNames::RECEIPT_SEALED, $agent->id, $agent->subject(), $agent->organizationId, ['receipt_id' => $receipt->id, 'seq' => $receipt->seq, 'hash' => $receipt->hash]));

        return $receipt;
    }
}
