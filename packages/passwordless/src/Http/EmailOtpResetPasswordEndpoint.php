<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\EmailOtp;
use Polaris\Passwordless\PasswordlessException;

use function is_string;

/**
 * `POST /email-otp/reset-password`: sets a new password with an email code and ends every session.
 */
final class EmailOtpResetPasswordEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly EmailOtp $otp)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $email = $this->email($input);
        $code = self::text($input, 'code');
        $password = $input->get('password');
        if ($email === null || $code === null || !is_string($password) || $password === '') {
            return $this->invalid('A valid email address, the code and the new password are required.');
        }
        try {
            $this->otp->resetPassword($email, $code, $password);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'password_reset']]);
    }
}
