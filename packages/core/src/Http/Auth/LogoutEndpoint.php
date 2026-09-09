<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Identity\SessionService;

/**
 * `POST /auth/logout` — revoke the caller's current session (the `sid` carried by its
 * access token). The stateless access token stays valid until it expires; the device can
 * no longer refresh.
 */
final class LogoutEndpoint extends Endpoint
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

        // Fail closed: a token with no session (`sid`) cannot end a session, so don't
        // report a logout that revoked nothing.
        $sessionId = (string) $token->getMetadata('sid');
        if ($sessionId === '') {
            return $this->unauthorized();
        }

        $this->sessions->logout($sessionId);

        return $this->respond(200, ['data' => ['status' => 'logged_out']]);
    }
}
