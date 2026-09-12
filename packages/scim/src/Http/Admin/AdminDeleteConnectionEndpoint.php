<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Recorder;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Connections;
use Polaris\Scim\Model\Connection;
use Psr\Clock\ClockInterface;

/**
 * `DELETE /admin/scim/connections/{id}`: an operator removes a connection outright (its external ids
 * and provenance with it; the provisioned users stay).
 */
final class AdminDeleteConnectionEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Connections $connections, private readonly Recorder $recorder, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connections->find((string) $input->get('id'));
        $principal = $this->authorize($input, Capability::Own, $connection?->organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        if (!$connection instanceof Connection) {
            return $this->missing('The connection does not exist.');
        }
        $this->connections->delete($connection->id);
        $client = $this->client($input);
        $this->recorder->record(AuditEvent::of(AuditNames::CONNECTION_DECOMMISSIONED, $this->clock->now(), $principal->id, $principal->type === Principal::TYPE_API_KEY ? AuditEvent::ACTOR_API_KEY : AuditEvent::ACTOR_ADMIN, $connection->id, $connection->organizationId, null, $client->ip, $client->userAgent, ['connection_name' => $connection->name, 'deleted' => true, 'actor_role' => $principal->role->value]));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
