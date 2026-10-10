<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Host;
use Polaris\Contract\DatabaseAdapter;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_map;

/**
 * An agent's registration by its owner (`POST /agents/register`) or enrolment by a host
 * (`POST /agents/enroll`): the agent and its OAuth client, the capabilities asked at once (the owner's
 * list, or the host's defaults: auto-approved by policy, the rest waiting for the owner in an `in_app`
 * approval), and the event.
 */
final class Registrations
{
    public function __construct(
        private readonly Agents $agents,
        private readonly GrantRequests $requests,
        private readonly DatabaseAdapter $database,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $fields `name`, `mode`, `auth`, `jwk`
     * @param list<mixed> $asked
     * @return array{agent: Agent, secret: string|null, grants: list<Grant>, approval: Approval|null}
     * @throws AgentException
     */
    public function register(array $fields, string $ownerType, string $ownerId, ?string $organizationId, string $createdBy, array $asked, ?string $ip, ?string $userAgent): array
    {
        $registered = $this->create($fields, $ownerType, $ownerId, $organizationId, $createdBy, null, $asked, false, $ip, $userAgent);
        $agent = $registered['agent'];
        $this->events->dispatch(AgentEvent::byUser(AuditNames::REGISTERED, $agent->id, $createdBy, $organizationId, ['name' => $agent->name, 'mode' => $agent->mode, 'auth' => $agent->auth, 'owner_type' => $ownerType], $ip, $userAgent));

        return $registered;
    }

    /**
     * @param array<string, mixed> $fields
     * @return array{agent: Agent, secret: string|null, grants: list<Grant>, approval: Approval|null}
     * @throws AgentException
     */
    public function enroll(Host $host, array $fields, ?string $ip, ?string $userAgent): array
    {
        $enrolled = $this->create($fields, $host->ownerType, $host->ownerId, $host->organizationId, $host->createdBy, $host->id, $host->defaultCapabilities, true, $ip, $userAgent);
        $agent = $enrolled['agent'];
        $this->events->dispatch(AgentEvent::byAgent(AuditNames::ENROLLED, $agent->id, $agent->subject(), $agent->organizationId, ['host_id' => $host->id, 'name' => $agent->name, 'mode' => $agent->mode, 'auth' => $agent->auth], $ip, $userAgent));

        return $enrolled;
    }

    /**
     * The `201` body: the agent, the secret once, its grants and the approval the owner must decide.
     *
     * @param array{agent: Agent, secret: string|null, grants: list<Grant>, approval: Approval|null} $registered
     * @return array<string, mixed>
     */
    public function response(array $registered): array
    {
        $data = $registered['agent']->toArray();
        if ($registered['secret'] !== null) {
            $data['client_secret'] = $registered['secret'];
        }
        $data['grants'] = array_map(static fn(Grant $grant): array => $grant->toArray(), $registered['grants']);
        $data['approval'] = $registered['approval'] === null ? null : $this->requests->approvalResponse($registered['approval']);

        return ['data' => $data];
    }

    /**
     * @param array<string, mixed> $fields
     * @param list<mixed> $asked
     * @return array{agent: Agent, secret: string|null, grants: list<Grant>, approval: Approval|null}
     */
    private function create(array $fields, string $ownerType, string $ownerId, ?string $organizationId, string $createdBy, ?string $hostId, array $asked, bool $byAgent, ?string $ip, ?string $userAgent): array
    {
        return $this->database->transaction(function () use ($fields, $ownerType, $ownerId, $organizationId, $createdBy, $hostId, $asked, $byAgent, $ip, $userAgent): array {
            [$agent, $secret] = $this->agents->create($fields, $ownerType, $ownerId, $organizationId, $createdBy, $hostId);
            $grants = [];
            $approval = null;
            if ($asked !== []) {
                // What the owner cannot decide at once waits in their own client's list.
                $requested = $this->requests->request($agent, $asked, Approval::METHOD_IN_APP, null, null, $byAgent, $ip, $userAgent);
                $grants = $requested['grants'];
                $approval = $requested['approval'];
            }

            return ['agent' => $agent, 'secret' => $secret, 'grants' => $grants, 'approval' => $approval];
        });
    }
}
