<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;

use function array_map;
use function is_array;

/**
 * `GET /orgs/{id}/sso/providers`: the organization's providers, never the secrets.
 */
final class ListProvidersEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Providers $providers)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }

        return $this->respond(200, ['data' => array_map(static fn(Provider $provider): array => $provider->toArray(), $this->providers->forOrganization($scope[1]))]);
    }
}
