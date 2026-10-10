<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;

/**
 * `GET /admin/oauth/clients`: every client, for the operators.
 */
final class AdminListClientsEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Clients $clients)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $data = [];
        foreach ($this->clients->all() as $client) {
            if ($principal->covers($client->organizationId)) {
                $data[] = $client->toArray();
            }
        }

        return $this->respond(200, ['data' => $data]);
    }
}
