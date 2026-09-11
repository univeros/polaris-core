<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Users;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Exception\UserNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `DELETE /admin/users/{id}`: anonymises the account (core's erasure) and ends every session.
 */
final class DeleteUserEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Manage);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        if ($userId === $principal->id) {
            return $this->conflict('You cannot delete your own account.');
        }
        try {
            $this->users->delete($principal->id, $userId);
        } catch (UserNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        }
        $this->audit->record(AdminAudit::USER_DELETED, $principal, $userId, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}
