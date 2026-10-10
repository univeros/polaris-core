<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Ciba;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;
use Psr\EventDispatcher\EventDispatcherInterface;

use function preg_match;

/**
 * `POST /oauth2/ciba` (OpenID CIBA, poll mode): a client asks a user, named by `login_hint` (their
 * email), to approve a sign-in; `oauth.ciba_requested` lets the host notify them.
 */
final class CibaEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Ciba $ciba, private readonly Scopes $scopes, private readonly Discovery $discovery, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $client = $this->authenticatedClient($this->clients, $this->discovery, $input, '/oauth2/ciba');
            $resource = self::text($input, 'resource');
            if ($resource !== null && preg_match('~^https?://[^\s#]+$~', $resource) !== 1) {
                throw new OAuthException(OAuthException::INVALID_TARGET, 'resource must be an absolute URI.');
            }
            [$response, $request] = $this->ciba->request($client, $this->scopes->parse(self::text($input, 'scope'), $client), self::text($input, 'login_hint'), self::text($input, 'binding_message'), $resource);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CIBA_REQUESTED, $request->userId, $client->clientId, null, ['auth_req_id' => $request->id, 'binding_message' => $request->bindingMessage, 'scopes' => $request->scopes], $context->ip, $context->userAgent));

        return $this->tokenResponse($response);
    }
}
