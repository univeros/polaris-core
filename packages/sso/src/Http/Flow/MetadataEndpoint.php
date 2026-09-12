<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Http\SsoEndpoint;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\Saml\SamlProtocol;
use Polaris\Sso\Sp;

/**
 * `GET /sso/metadata/{providerId}`: the SP metadata the IdP is configured with.
 */
final class MetadataEndpoint extends SsoEndpoint
{
    public function __construct(private readonly Providers $providers, private readonly SamlProtocol $saml, private readonly Sp $sp)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $provider = $this->providers->find((string) $input->get('providerId'));
        if (!$provider instanceof Provider || $provider->type !== Provider::SAML) {
            return $this->problem(404, 'sso/provider_not_found', 'Provider not found', 'No SAML provider has this id.');
        }

        return new Result(200, [], ['Content-Type' => 'application/samlmetadata+xml'], raw: $this->saml->metadata($provider, $this->sp));
    }
}
