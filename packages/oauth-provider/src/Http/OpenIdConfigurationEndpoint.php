<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Discovery;

/**
 * `GET /.well-known/openid-configuration`: OpenID Connect Discovery, exactly what is enabled.
 */
final class OpenIdConfigurationEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Discovery $discovery)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return new Result(200, $this->discovery->openId(), ['Cache-Control' => 'public, max-age=3600']);
    }
}
