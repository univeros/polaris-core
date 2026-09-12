<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\SsoAudit;

use function is_array;

/**
 * `DELETE /orgs/{id}/sso/providers/{providerId}`: the provider and its domains.
 */
final class DeleteProviderEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Providers $providers, private readonly Domains $domains, private readonly SsoAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        [$token, $organizationId] = $scope;
        $provider = $this->provider($this->providers, $input, $organizationId);
        if (!$provider instanceof Provider) {
            return $provider;
        }
        $this->domains->deleteForProvider($provider->id);
        $this->providers->delete($provider->id);
        $this->audit->record(AuditNames::PROVIDER_DELETED, 'user', $this->actorId($token), $provider->id, $organizationId, ['type' => $provider->type, 'name' => $provider->name], $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
