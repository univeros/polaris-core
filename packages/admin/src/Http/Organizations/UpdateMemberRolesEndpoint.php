<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Organizations;

use InvalidArgumentException;
use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Exception\LastOwnerException;
use Polaris\Exception\MemberNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_values;
use function is_array;
use function is_string;

/**
 * `PATCH /admin/organizations/{id}/members/{userId}/roles`: replaces a member's roles.
 */
final class UpdateMemberRolesEndpoint extends AdminEndpoint
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
        $roles = $input->get('roles');
        if (!is_array($roles) || $roles === []) {
            return $this->invalid('roles must be a non-empty list of role slugs.');
        }
        foreach ($roles as $role) {
            if (!is_string($role) || $role === '') {
                return $this->invalid('roles must be a non-empty list of role slugs.');
            }
        }
        if ($this->organizations->find($organizationId) === null) {
            return $this->missing('The organization does not exist.');
        }
        $userId = (string) $input->get('userId');
        try {
            $this->organizations->setMemberRoles($organizationId, $userId, array_values($roles), $principal->id);
        } catch (MemberNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->invalid($exception->getMessage());
        } catch (LastOwnerException $exception) {
            return $this->conflict($exception->getMessage());
        }
        $this->audit->record(AdminAudit::MEMBER_ROLES_CHANGED, $principal, $userId, $organizationId, ['roles' => array_values($roles)], $this->client($input));

        return $this->respond(200, ['data' => ['roles' => array_values($roles)]]);
    }
}
