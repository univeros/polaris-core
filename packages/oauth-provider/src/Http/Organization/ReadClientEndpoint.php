<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Model\Client;

use function is_array;

/**
 * `GET /orgs/{id}/oauth/clients/{clientId}`: one client of the organization.
 */
final class ReadClientEndpoint extends OrgClientEndpoint
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
        $client = $this->orgClient($this->clients, $input, $scope[1]);

        return $client instanceof Client ? $this->respond(200, ['data' => $client->toArray()]) : $client;
    }
}
