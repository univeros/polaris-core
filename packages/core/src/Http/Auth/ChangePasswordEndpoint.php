<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\AccountDisabledException;
use Polaris\Exception\InvalidCredentialsException;
use Polaris\Exception\InvalidPasswordException;
use Polaris\Identity\PasswordResetService;

/**
 * `POST /auth/password/change` — change the password while authenticated. Keeps the
 * caller's current session and revokes the rest. Requires the current password (a re-auth;
 * MFA step-up enforcement arrives with Phase 2).
 */
final class ChangePasswordEndpoint extends Endpoint
{
    public function __construct(private readonly PasswordResetService $passwords)
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

        $currentPassword = (string) $input->get('current_password', '');
        $newPassword = (string) $input->get('new_password', '');
        if ($currentPassword === '' || $newPassword === '') {
            return $this->unprocessable(['The current and new passwords are required.']);
        }

        $sessionId = (string) $token->getMetadata('sid');

        try {
            $this->passwords->change($userId, $currentPassword, $newPassword, $sessionId !== '' ? $sessionId : null, $this->client($input));
        } catch (InvalidCredentialsException) {
            return $this->respond(403, ['error' => 'invalid_credentials', 'message' => 'The current password is incorrect.']);
        } catch (AccountDisabledException) {
            return $this->respond(403, ['error' => 'account_disabled', 'message' => 'This account is disabled.']);
        } catch (InvalidPasswordException $exception) {
            return $this->unprocessable($exception->violations);
        }

        return $this->respond(200, ['data' => ['status' => 'password_changed']]);
    }
}
