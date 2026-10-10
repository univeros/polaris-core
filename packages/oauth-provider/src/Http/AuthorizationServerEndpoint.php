<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Discovery;

/**
 * `GET /.well-known/oauth-authorization-server` (RFC 8414): the authorization server's metadata.
 */
final class AuthorizationServerEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Discovery $discovery)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return new Result(200, $this->discovery->authorizationServer(), ['Cache-Control' => 'public, max-age=3600']);
    }
}
