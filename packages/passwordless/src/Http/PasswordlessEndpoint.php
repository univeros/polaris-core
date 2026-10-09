<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;

use function is_string;
use function trim;

/**
 * What every passwordless route shares: the problem document for a refused step, the input helpers and
 * the one answer every send gives, whether or not anything was sent.
 */
abstract class PasswordlessEndpoint extends Endpoint
{
    protected function refuse(PasswordlessException $exception): Result
    {
        $errors = $exception->errors === [] ? [] : ['errors' => $exception->errors];

        return match ($exception->reason) {
            PasswordlessException::REDIRECT_NOT_ALLOWED => $this->problem(422, 'passwordless/redirect_not_allowed', 'Redirect not allowed', $exception->getMessage()),
            PasswordlessException::CODE_INVALID => $this->problem(422, 'passwordless/code_invalid', 'Invalid code', 'The code is wrong, used or expired.'),
            PasswordlessException::TOKEN_INVALID => $this->problem(422, 'passwordless/token_invalid', 'Invalid token', 'The token is unknown, used or expired.'),
            PasswordlessException::ACCOUNT_DISABLED => $this->problem(403, 'passwordless/account_disabled', 'Account disabled', 'This account is disabled.'),
            PasswordlessException::PASSWORD_INVALID => $this->problem(422, 'passwordless/password_invalid', 'Invalid password', $exception->getMessage(), $errors),
            PasswordlessException::PHONE_TAKEN => $this->problem(409, 'passwordless/phone_taken', 'Phone taken', 'Another account uses this phone number.'),
            PasswordlessException::SESSION_REQUIRED => $this->problem(403, 'passwordless/session_required', 'Session required', 'A one-time token needs a live session.'),
            default => $this->problem(422, 'passwordless/invalid_input', 'Invalid input', $exception->getMessage(), $errors),
        };
    }

    protected function invalid(string $message): Result
    {
        return $this->problem(422, 'passwordless/invalid_input', 'Invalid input', $message, ['errors' => [$message]]);
    }

    protected function sent(): Result
    {
        return $this->respond(202, ['data' => ['status' => 'sent']]);
    }

    protected static function text(Input $input, string $field): ?string
    {
        $value = $input->get($field);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected function email(Input $input): ?string
    {
        $email = self::text($input, 'email');

        return $email !== null && $this->isEmail($email) ? $email : null;
    }
}
