<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Model\Organization;
use Polaris\Repository\OrganizationRepository;

/**
 * `DELETE /orgs/{id}` — soft-delete the organization (`status=suspended`, emits `org.deleted`).
 *
 * Gated on `org.delete` (held only by owners) by the AuthorizationMiddleware and step-up-gated;
 * this domain enforces cross-tenant isolation. An already-deleted organization reads as not found.
 * Purge-per-retention is ops tooling, not this API.
 */
final class DeleteOrganizationEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ORG_DELETE];

    public function __construct(
        private readonly OrganizationRepository $organizations,
        private readonly OrganizationService $service,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $organizationId = (string) $input->get('id');
        if ($this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->forbidden('That organization is not your active organization.');
        }

        $organization = $this->organizations->find($organizationId);
        if (!$organization instanceof Organization || $organization->status !== Organization::STATUS_ACTIVE) {
            return $this->notFound('The organization does not exist.');
        }

        $this->service->softDelete($organization, (string) $token->getMetadata('sub'));

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}
