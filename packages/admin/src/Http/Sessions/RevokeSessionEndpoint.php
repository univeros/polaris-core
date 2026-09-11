<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Sessions;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Identity\SessionService;

/**
 * `DELETE /admin/users/{id}/sessions/{sessionId}`: ends one session of the user.
 */
final class RevokeSessionEndpoint extends AdminEndpoint
{
    public function __construct(private readonly SessionService $sessions, private readonly AdminAudit $audit)
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
        $sessionId = (string) $input->get('sessionId');
        if (!$this->sessions->revoke($userId, $sessionId)) {
            return $this->missing('The session does not exist for this user.');
        }
        $this->audit->record(AdminAudit::SESSION_REVOKED, $principal, $userId, data: ['session_id' => $sessionId], client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
