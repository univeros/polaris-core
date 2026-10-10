<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Organization;

use Polaris\Contract\TokenInterface;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Http\OAuthEndpoint;
use Polaris\OAuth\Model\Client;

/**
 * What the organization's self-service routes share: core's bearer and `org.update` gate the route
 * (the authorization middleware); the organization in the path must be the token's active one (a
 * superadmin excepted), then the client must belong to it. `trusted` is not theirs to set.
 */
abstract class OrgClientEndpoint extends OAuthEndpoint
{
    /**
     * @return array{TokenInterface, string}|Result
     */
    protected function organization(Input $input): array|Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $organizationId = (string) $input->get('id');
        if ($organizationId === '' || $this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->problem(403, 'oauth/forbidden', 'Forbidden', 'That organization is not your active organization.');
        }

        return [$token, $organizationId];
    }

    protected function orgClient(Clients $clients, Input $input, string $organizationId): Client|Result
    {
        $client = $clients->findById((string) $input->get('clientId'));
        if (!$client instanceof Client || $client->organizationId !== $organizationId) {
            return $this->problem(404, 'oauth/not_found', 'Not found', 'The client does not exist in this organization.');
        }

        return $client;
    }
}
