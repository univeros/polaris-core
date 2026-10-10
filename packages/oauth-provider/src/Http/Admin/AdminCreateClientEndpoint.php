<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\Http\Endpoint;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `POST /admin/oauth/clients`: an operator registers a client, instance-wide or for an organization,
 * and may mark it trusted (its users are not asked for consent).
 */
final class AdminCreateClientEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Clients $clients, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = self::text($input->get('organization_id'));
        $principal = $this->authorize($input, Capability::Own, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        try {
            $issued = $this->clients->create($input->all(), $organizationId, $principal->id, true);
        } catch (OAuthException $exception) {
            return $this->problem($exception->status, 'oauth/' . $exception->error, 'Invalid client metadata', $exception->description, ['error' => $exception->error, 'error_description' => $exception->description]);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_CREATED, $principal->type === Principal::TYPE_API_KEY ? null : $principal->id, $issued->client->clientId, $organizationId, ['name' => $issued->client->name, 'how' => 'admin', 'trusted' => $issued->client->trusted], $context->ip, $context->userAgent));

        return $this->respond(201, ['data' => [...$issued->client->toArray(), 'client_secret' => $issued->secret]]);
    }
}
