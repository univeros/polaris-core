<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\SsoAudit;

/**
 * `DELETE /admin/sso/providers/{id}`: an operator removes a provider and its domains.
 */
final class AdminDeleteProviderEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Providers $providers, private readonly Domains $domains, private readonly SsoAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $provider = $this->providers->find((string) $input->get('id'));
        $principal = $this->authorize($input, Capability::Own, $provider?->organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        if (!$provider instanceof Provider) {
            return $this->missing('The provider does not exist.');
        }
        $this->domains->deleteForProvider($provider->id);
        $this->providers->delete($provider->id);
        $this->audit->record(AuditNames::PROVIDER_DELETED, $principal->type === Principal::TYPE_API_KEY ? 'api_key' : 'admin', $principal->id, $provider->id, $provider->organizationId, ['type' => $provider->type, 'name' => $provider->name, 'actor_role' => $principal->role->value], $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
