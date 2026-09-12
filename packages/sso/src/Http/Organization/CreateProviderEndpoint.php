<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Providers;
use Polaris\Sso\SsoAudit;

use function is_array;

/**
 * `POST /orgs/{id}/sso/providers`: a SAML or OIDC provider for the organization.
 */
final class CreateProviderEndpoint extends OrgEndpoint
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
        $fields = ProviderInput::from($input->all());
        if (is_array($fields)) {
            return $this->invalid($fields[0], $fields);
        }
        $provider = $this->providers->create($organizationId, $fields->type, $fields->name, $fields->issuer, $fields->config, $fields->attributes, $fields->jit, $fields->redirectUris, $fields->enabled, $this->actorId($token));
        $this->audit->record(AuditNames::PROVIDER_CREATED, 'user', $this->actorId($token), $provider->id, $organizationId, ['type' => $provider->type, 'name' => $provider->name], $this->client($input));

        return $this->respond(201, ['data' => $provider->toArray()]);
    }
}
