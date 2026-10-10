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
use Polaris\OAuth\Tokens;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_array;

/**
 * `DELETE /orgs/{id}/oauth/clients/{clientId}`: the client and every token it holds go.
 */
final class DeleteClientEndpoint extends OrgClientEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Tokens $tokens, private readonly EventDispatcherInterface $events)
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
        $this->tokens->deleteForClient($client->clientId);
        $this->clients->delete($client);
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_DELETED, $this->actorId($token), $client->clientId, $organizationId, ['name' => $client->name], $context->ip, $context->userAgent));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
