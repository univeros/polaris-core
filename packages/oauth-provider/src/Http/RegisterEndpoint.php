<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Settings;
use Psr\EventDispatcher\EventDispatcherInterface;

use function explode;
use function is_string;

/**
 * `POST /oauth2/register` (RFC 7591, dynamic client registration): off by default; when on, anyone
 * registers a client and gets its id (and secret, once). Never trusted.
 */
final class RegisterEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Settings $settings, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if (!$this->settings->dynamicRegistration) {
            return $this->refuse(new OAuthException(OAuthException::REGISTRATION_DISABLED, 'Dynamic client registration is off on this server; ask an operator or an organization admin for a client.', 403));
        }
        $fields = $input->all();
        $fields['name'] = $fields['client_name'] ?? $fields['name'] ?? null;
        $method = $fields['token_endpoint_auth_method'] ?? null;
        $fields['type'] = $method === Client::AUTH_NONE ? Client::TYPE_PUBLIC : Client::TYPE_CONFIDENTIAL;
        if (is_string($fields['scope'] ?? null) && !isset($fields['scopes'])) {
            $fields['scopes'] = $fields['scope'] === '' ? [] : explode(' ', $fields['scope']);
        }
        try {
            $issued = $this->clients->create($fields, null, null, false);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CLIENT_CREATED, null, $issued->client->clientId, null, ['name' => $issued->client->name, 'how' => 'dynamic_registration'], $context->ip, $context->userAgent));
        $body = ['client_id' => $issued->client->clientId, 'client_name' => $issued->client->name, ...$issued->client->toArray()];
        unset($body['id'], $body['organization_id'], $body['created_by'], $body['trusted'], $body['disabled_at']);
        if ($issued->secret !== null) {
            $body['client_secret'] = $issued->secret;
            $body['client_secret_expires_at'] = 0;
        }

        return new Result(201, $body, self::NO_STORE);
    }
}
