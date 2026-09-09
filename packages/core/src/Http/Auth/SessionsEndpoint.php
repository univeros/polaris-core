<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Identity\SessionService;

/**
 * `GET /auth/sessions` — list the authenticated user's active sessions (devices), with the
 * calling session flagged `current` (matched by `sid`).
 */
final class SessionsEndpoint extends Endpoint
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

        $currentSessionId = (string) $token->getMetadata('sid');

        return $this->respond(200, ['data' => ['sessions' => $this->sessions->listFor($userId, $currentSessionId)]]);
    }
}
