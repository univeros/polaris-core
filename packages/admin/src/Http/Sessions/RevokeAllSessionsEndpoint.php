<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Sessions;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Identity\SessionService;
use Polaris\Model\RefreshToken;

/**
 * `DELETE /admin/users/{id}/sessions`: ends every session of the user.
 */
final class RevokeAllSessionsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users, private readonly SessionService $sessions, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Support);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        if ($this->users->find($userId) === null) {
            return $this->missing('The user does not exist.');
        }
        $count = $this->sessions->revokeAll($userId, RefreshToken::REASON_ADMIN);
        $this->audit->record(AdminAudit::SESSIONS_REVOKED, $principal, $userId, data: ['count' => $count], client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'revoked', 'count' => $count]]);
    }
}
