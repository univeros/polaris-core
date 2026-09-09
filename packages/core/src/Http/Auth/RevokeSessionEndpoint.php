<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Identity\SessionService;

use function trim;

/**
 * `DELETE /auth/sessions/{id}` — revoke a specific session of the authenticated user. A
 * session that does not belong to the caller returns `404` (no cross-user disclosure).
 */
final class RevokeSessionEndpoint extends Endpoint
{
    public function __construct(private readonly SessionService $sessions)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        $sessionId = trim((string) $input->get('id', ''));

        if ($userId === '') {
            return $this->unauthorized();
        }

        if ($sessionId === '') {
            return $this->unprocessable(['A session id is required.']);
        }

        if (!$this->sessions->revoke($userId, $sessionId)) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'Session not found.']);
        }

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
