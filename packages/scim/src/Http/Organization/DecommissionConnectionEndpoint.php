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
 * `DELETE /orgs/{id}/scim/connections/{connectionId}`: decommissions the connection; the token stops,
 * the provisioned users stay.
 */
final class DecommissionConnectionEndpoint extends OrgEndpoint
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
        if ($connection->active()) {
            $this->connections->decommission($connection);
            $this->audit->recordUser(AuditNames::CONNECTION_DECOMMISSIONED, $this->actorId($token), $connection, [], $this->client($input));
        }

        return $this->respond(200, ['data' => $this->state($connection)]);
    }
}
