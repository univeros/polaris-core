<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\EmailOtp;
use Polaris\Passwordless\PasswordlessException;

/**
 * `POST /email-otp/verify-email`: verifies the email with a code.
 */
final class EmailOtpVerifyEmailEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly EmailOtp $otp)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $email = $this->email($input);
        $code = self::text($input, 'code');
        if ($email === null || $code === null) {
            return $this->invalid('A valid email address and the code are required.');
        }
        try {
            $this->otp->verifyEmail($email, $code);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'verified']]);
    }
}
