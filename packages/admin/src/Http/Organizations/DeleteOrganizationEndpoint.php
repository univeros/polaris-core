<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Organizations;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `DELETE /admin/organizations/{id}`: soft-deletes the organization (core's suspension) and ends its
 * members' sessions on it.
 */
final class DeleteOrganizationEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Organizations $organizations, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = (string) $input->get('id');
        $principal = $this->authorize($input, Capability::Manage, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $organization = $this->organizations->find($organizationId);
        if ($organization === null) {
            return $this->missing('The organization does not exist.');
        }
        $this->organizations->delete($organization, $principal->id);
        $this->audit->record(AdminAudit::ORGANIZATION_DELETED, $principal, null, $organizationId, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'suspended']]);
    }
}
