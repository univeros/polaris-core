<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;

use function is_array;

/**
 * `GET /orgs/{id}/oauth/clients`: the organization's clients.
 */
final class ListClientsEndpoint extends OrgClientEndpoint
{
    public function __construct(private readonly Clients $clients)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        $data = [];
        foreach ($this->clients->forOrganization($scope[1]) as $client) {
            $data[] = $client->toArray();
        }

        return $this->respond(200, ['data' => $data]);
    }
}
