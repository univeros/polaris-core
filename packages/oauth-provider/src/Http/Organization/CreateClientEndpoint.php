<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_array;

/**
 * `POST /orgs/{id}/oauth/clients`: a client for the organization; the secret is in this response only.
 */
final class CreateClientEndpoint extends OrgClientEndpoint
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
        try {
            $issued = $this->clients->create($input->all(), $organizationId, $this->actorId($token), false);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_CREATED, $this->actorId($token), $issued->client->clientId, $organizationId, ['name' => $issued->client->name, 'how' => 'organization'], $context->ip, $context->userAgent));

        return $this->respond(201, ['data' => [...$issued->client->toArray(), 'client_secret' => $issued->secret]]);
    }
}
