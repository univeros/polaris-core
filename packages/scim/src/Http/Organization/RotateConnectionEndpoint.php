<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Model\Connection;

use function is_array;

/**
 * `POST /orgs/{id}/scim/connections/{connectionId}/rotate`: a new token, in this response only; the
 * previous one stops at once.
 */
final class RotateConnectionEndpoint extends OrgEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        [$token, $organizationId] = $scope;
        $connection = $this->connection($input, $organizationId);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        if (!$connection->active()) {
            return $this->problem(409, 'scim/conflict', 'Conflict', 'The connection is decommissioned.');
        }
        $secret = $this->connections->rotate($connection);
        $this->audit->recordUser(AuditNames::CONNECTION_ROTATED, $this->actorId($token), $connection, [], $this->client($input));

        return $this->respond(200, ['data' => [...$this->state($connection), 'token' => $secret]]);
    }
}
