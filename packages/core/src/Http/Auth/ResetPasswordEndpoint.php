<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\InvalidPasswordException;
use Polaris\Exception\InvalidResetTokenException;
use Polaris\Identity\PasswordResetService;

use function trim;

/**
 * `POST /auth/password/reset` — set a new password from a reset token. On success every
 * session is revoked (logout everywhere). A bad/expired token returns a generic `400`.
 */
final class ResetPasswordEndpoint extends Endpoint
{
    public function __construct(private readonly PasswordResetService $passwords)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = trim((string) $input->get('token', ''));
        $newPassword = (string) $input->get('new_password', '');

        if ($token === '' || $newPassword === '') {
            return $this->unprocessable(['A token and new password are required.']);
        }

        try {
            $this->passwords->reset($token, $newPassword, $this->client($input));
        } catch (InvalidPasswordException $exception) {
            return $this->unprocessable($exception->violations);
        } catch (InvalidResetTokenException) {
            return $this->respond(401, ['error' => 'invalid_token', 'message' => 'The reset token is invalid or has expired.']);
        }

        return $this->respond(200, ['data' => ['status' => 'password_reset']]);
    }
}
