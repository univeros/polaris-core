<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Tokens;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `POST /oauth2/revoke` (RFC 7009): the client ends one of its own tokens; a refresh token takes its
 * family with it. An unknown token is not an error.
 */
final class RevokeEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Tokens $tokens, private readonly Discovery $discovery, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $client = $this->authenticatedClient($this->clients, $this->discovery, $input, '/oauth2/revoke');
            $token = self::text($input, 'token');
            if ($token === null) {
                throw new OAuthException(OAuthException::INVALID_REQUEST, 'token is required.');
            }
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $revoked = $this->tokens->revoke($token, $client);
        if ($revoked !== null) {
            $context = $this->client($input);
            $this->events->dispatch(new OAuthEvent(AuditNames::TOKEN_REVOKED, $revoked->userId, $client->clientId, $revoked->organizationId, ['kind' => $revoked->kind], $context->ip, $context->userAgent));
        }

        return new Result(200, ['data' => ['status' => 'revoked']], self::NO_STORE);
    }
}
