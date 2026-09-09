<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Identity\SessionService;

/**
 * `POST /auth/logout-all` — revoke every session for the authenticated user (e.g. after a
 * security scare). Emits `auth.sessions_revoked`.
 */
final class LogoutAllEndpoint extends Endpoint
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
        if ($userId === '') {
            return $this->unauthorized();
        }

        $this->sessions->logoutAll($userId, $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'logged_out_all']]);
    }
}
