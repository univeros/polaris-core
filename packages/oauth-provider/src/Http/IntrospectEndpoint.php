<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Tokens;

/**
 * `POST /oauth2/introspect` (RFC 7662): an authenticated client asks whether a token is live and
 * what it carries.
 */
final class IntrospectEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Tokens $tokens, private readonly Discovery $discovery)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $client = $this->authenticatedClient($this->clients, $this->discovery, $input, '/oauth2/introspect');
            if ($client->tokenEndpointAuthMethod === Client::AUTH_NONE) {
                throw new OAuthException(OAuthException::INVALID_CLIENT, 'Introspection is for clients that authenticate (RFC 7662 §2.1).', 401);
            }
            $token = self::text($input, 'token');
            if ($token === null) {
                throw new OAuthException(OAuthException::INVALID_REQUEST, 'token is required.');
            }
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }

        return new Result(200, $this->tokens->introspect($token), self::NO_STORE);
    }
}
