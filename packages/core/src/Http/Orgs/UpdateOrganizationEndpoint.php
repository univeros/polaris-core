<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use InvalidArgumentException;
use Override;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Model\Organization;
use Polaris\Repository\OrganizationRepository;

use function is_string;

/**
 * `PATCH /orgs/{id}` — rename the organization.
 *
 * Gated on `org.update` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation. A soft-deleted organization reads as not found.
 */
final class UpdateOrganizationEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ORG_UPDATE];

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

        $name = $input->get('name');
        if (!is_string($name)) {
            return $this->unprocessable(['A name is required.']);
        }

        $organization = $this->organizations->find($organizationId);
        if (!$organization instanceof Organization || $organization->status !== Organization::STATUS_ACTIVE) {
            return $this->notFound('The organization does not exist.');
        }

        try {
            $organization = $this->service->update($organization, $name, (string) $token->getMetadata('sub'));
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        }

        return $this->respond(200, [
            'data' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
                'status' => $organization->status,
            ],
        ]);
    }
}
