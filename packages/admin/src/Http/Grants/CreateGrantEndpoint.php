<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Grants;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Grants;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Admin\Users;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /admin/grants`: gives a user an operator role, replacing their previous grant.
 */
final class CreateGrantEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Grants $grants, private readonly Users $users, private readonly Organizations $organizations, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = self::text($input->get('scope')) ?? Principal::SCOPE_INSTANCE;
        $principal = $this->authorize($input, Capability::Own, $scope === Principal::SCOPE_INSTANCE ? null : $scope);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = self::text($input->get('user_id'));
        if ($userId === null) {
            return $this->invalid('user_id is required.');
        }
        $role = Role::tryFromInput($input->get('role'));
        if ($role === null) {
            return $this->invalid('role must be viewer, support, admin or owner.');
        }
        $expiresAt = self::datetime($input->get('expires_at'));
        if ($expiresAt === false) {
            return $this->invalid('expires_at must be an ISO-8601 datetime.');
        }
        if ($this->users->find($userId) === null) {
            return $this->missing('The user does not exist.');
        }
        if ($scope !== Principal::SCOPE_INSTANCE && $this->organizations->find($scope) === null) {
            return $this->invalid('scope must be "instance" or an organization id.');
        }
        $grant = $this->grants->grant($userId, $role, $scope, $expiresAt, $principal->id);
        $this->audit->record(AdminAudit::GRANT_CREATED, $principal, $userId, $scope === Principal::SCOPE_INSTANCE ? null : $scope, ['grant_id' => $grant->id, 'role' => $role->value], $this->client($input));

        return $this->respond(201, ['data' => $grant->toArray()]);
    }
}
