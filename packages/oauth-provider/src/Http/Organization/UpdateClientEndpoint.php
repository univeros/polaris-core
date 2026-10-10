<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_array;

/**
 * `PATCH /orgs/{id}/oauth/clients/{clientId}`: the client's name, redirect URIs, grants, scopes, keys,
 * DPoP binding, links, or `disabled`.
 */
final class UpdateClientEndpoint extends OrgClientEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        [$token, $organizationId] = $scope;
        $client = $this->orgClient($this->clients, $input, $organizationId);
        if (!$client instanceof Client) {
            return $client;
        }
        $fields = $input->all();
        unset($fields['id'], $fields['clientId']);
        try {
            $changes = $this->clients->update($client, $fields, false);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        if ($changes !== []) {
            $context = $this->client($input);
            $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_UPDATED, $this->actorId($token), $client->clientId, $organizationId, ['changes' => $changes], $context->ip, $context->userAgent));
        }

        return $this->respond(200, ['data' => $client->toArray()]);
    }
}
