<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Organizations;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /admin/organizations/{id}`: the organization with its members and their roles.
 */
final class ReadOrganizationEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Organizations $organizations)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = (string) $input->get('id');
        $principal = $this->authorize($input, Capability::Read, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $organization = $this->organizations->find($organizationId);

        return $organization === null ? $this->missing('The organization does not exist.') : $this->respond(200, ['data' => $this->organizations->read($organization)]);
    }
}
