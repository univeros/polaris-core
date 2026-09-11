<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Sessions;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Identity\SessionService;

/**
 * `GET /admin/users/{id}/sessions`: the user's active sessions.
 */
final class ListSessionsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users, private readonly SessionService $sessions)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        if ($this->users->find($userId) === null) {
            return $this->missing('The user does not exist.');
        }

        return $this->respond(200, ['data' => $this->sessions->listFor($userId, '')]);
    }
}
