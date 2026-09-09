<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\RoleService;

/**
 * `GET /orgs/{id}/roles` — list the organization's roles with their permission keys.
 *
 * Gated on `roles.read` by the AuthorizationMiddleware; this domain enforces cross-tenant
 * isolation.
 */
final class ListRolesEndpoint extends Endpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::ROLES_READ];

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

        return $this->respond(200, ['data' => $this->roles->listRoles($organizationId)]);
    }
}
