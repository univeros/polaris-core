<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Principals;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Providers;

/**
 * `GET /admin/sso/providers`: every organization's providers for the operators; an organization-scoped
 * principal sees their organization's.
 */
final class AdminListProvidersEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Providers $providers)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = self::text($input->get('organization_id'));
        $caller = $input->attribute(Principals::ATTRIBUTE);
        if ($organizationId === null && $caller instanceof Principal && $caller->scope !== Principal::SCOPE_INSTANCE) {
            $organizationId = $caller->scope;
        }
        $principal = $this->authorize($input, Capability::Read, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $limit = self::positiveInt($input->get('limit'), Providers::DEFAULT_LIMIT);
        if ($limit === false) {
            return $this->invalid('limit must be a positive integer.');
        }

        return $this->respond(200, $this->providers->list($organizationId, self::text($input->get('cursor')), $limit));
    }
}
