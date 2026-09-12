<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Connections;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Resources;
use Polaris\Scim\ScimAudit;
use Polaris\Scim\Sp;

use function is_array;

/**
 * `GET /orgs/{id}/scim/connections/{connectionId}`: the connection, its sync state and the base URL
 * the directory is configured with.
 */
final class ReadConnectionEndpoint extends OrgEndpoint
{
    public function __construct(Connections $connections, Resources $resources, ScimAudit $audit, private readonly Sp $sp)
    {
        parent::__construct($connections, $resources, $audit);
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        $connection = $this->connection($input, $scope[1]);
        if (!$connection instanceof Connection) {
            return $connection;
        }

        return $this->respond(200, ['data' => [...$this->state($connection), 'scim_base_url' => $this->sp->location($connection->id)]]);
    }
}
