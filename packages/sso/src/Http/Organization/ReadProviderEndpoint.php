<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\Sp;

use function is_array;

/**
 * `GET /orgs/{id}/sso/providers/{providerId}`: the provider and the SP URLs its IdP needs.
 */
final class ReadProviderEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Providers $providers, private readonly Sp $sp)
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

        return $this->respond(200, ['data' => [...$provider->toArray(), 'sp' => [
            'entity_id' => $this->sp->entityId($provider->id),
            'acs_url' => $this->sp->acsUrl($provider->id),
            'slo_url' => $this->sp->sloUrl($provider->id),
            'metadata_url' => $this->sp->metadataUrl($provider->id),
        ]]]);
    }
}
