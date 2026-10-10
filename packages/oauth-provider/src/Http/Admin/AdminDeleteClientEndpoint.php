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
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Tokens;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `DELETE /admin/oauth/clients/{id}`: an operator removes a client and its tokens.
 */
final class AdminDeleteClientEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Clients $clients, private readonly Tokens $tokens, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $client = $this->clients->findById((string) $input->get('id'));
        $principal = $this->authorize($input, Capability::Own, $client?->organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        if (!$client instanceof Client) {
            return $this->missing('The client does not exist.');
        }
        $this->tokens->deleteForClient($client->clientId);
        $this->clients->delete($client);
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_DELETED, $principal->type === Principal::TYPE_API_KEY ? null : $principal->id, $client->clientId, $client->organizationId, ['name' => $client->name, 'how' => 'admin'], $context->ip, $context->userAgent));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
