<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\RoleService;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\RoleNotFoundException;

/**
 * `DELETE /orgs/{id}/roles/{roleId}` — delete a custom role; the DB cascade detaches it from all
 * memberships. System roles and the org's `owner` role are protected.
 *
 * Gated on `roles.manage` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation.
 */
final class DeleteRoleEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ROLES_MANAGE];

    public function __construct(private readonly RoleService $roles)
    {
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

        $roleId = (string) $input->get('roleId');
        if ($roleId === '') {
            return $this->unprocessable(['A role id is required.']);
        }

        try {
            $this->roles->delete((string) $token->getMetadata('sub'), $organizationId, $roleId);
        } catch (RoleNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}
