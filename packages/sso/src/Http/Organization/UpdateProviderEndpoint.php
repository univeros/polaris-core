<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\SsoAudit;

use function is_array;

/**
 * `PATCH /orgs/{id}/sso/providers/{providerId}`: the fields given replace the provider's; an absent
 * client_secret keeps the stored one.
 */
final class UpdateProviderEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Providers $providers, private readonly SsoAudit $audit)
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
        $fields = ProviderInput::from($input->all(), $provider);
        if (is_array($fields)) {
            return $this->invalid($fields[0], $fields);
        }
        $this->providers->update($provider, $fields->name, $fields->issuer, $fields->config, $fields->attributes, $fields->jit, $fields->redirectUris, $fields->enabled);
        $this->audit->record(AuditNames::PROVIDER_UPDATED, 'user', $this->actorId($token), $provider->id, $organizationId, ['enabled' => $provider->enabled], $this->client($input));

        return $this->respond(200, ['data' => $provider->toArray()]);
    }
}
