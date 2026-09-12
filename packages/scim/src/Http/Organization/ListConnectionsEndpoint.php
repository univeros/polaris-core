<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function is_array;

/**
 * `GET /orgs/{id}/scim/connections`: the organization's connections with their sync state, never the tokens.
 */
final class ListConnectionsEndpoint extends OrgEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        $data = [];
        foreach ($this->connections->forOrganization($scope[1]) as $connection) {
            $data[] = $this->state($connection);
        }

        return $this->respond(200, ['data' => $data]);
    }
}
