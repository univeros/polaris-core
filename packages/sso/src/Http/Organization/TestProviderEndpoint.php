<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Oidc\OidcProtocol;
use Polaris\Sso\Providers;
use Polaris\Sso\Saml\SamlProtocol;
use Polaris\Sso\Sp;

use function is_array;

/**
 * `POST /orgs/{id}/sso/providers/{providerId}/test`: whether the provider is complete and reachable
 * (OIDC: the discovery document and the JWKS; SAML: the certificate and the URLs).
 */
final class TestProviderEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Providers $providers, private readonly OidcProtocol $oidc, private readonly SamlProtocol $saml, private readonly Sp $sp)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        $provider = $this->provider($this->providers, $input, $scope[1]);
        if (!$provider instanceof Provider) {
            return $provider;
        }
        $problems = $provider->type === Provider::OIDC ? $this->oidc->check($provider) : $this->saml->check($provider, $this->sp);

        return $this->respond(200, ['data' => ['ok' => $problems === [], 'problems' => $problems]]);
    }
}
