<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\RoleService;

/**
 * `GET /permissions` — the full permission catalog (Polaris core ∪ host-contributed), for building
 * role-management UIs.
 *
 * Authenticated but not permission-gated: the catalog is the same for every tenant and carries no
 * org data, and a member needs it to render role pickers.
 */
final class ListPermissionsEndpoint extends Endpoint
{
    public function __construct(private readonly RoleService $roles)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if ($this->token($input) === null) {
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => $this->roles->permissionCatalog()]);
    }
}
