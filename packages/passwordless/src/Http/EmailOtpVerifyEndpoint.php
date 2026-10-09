<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\EmailOtp;
use Polaris\Passwordless\PasswordlessException;

/**
 * `POST /email-otp/verify`: signs in with an email code.
 */
final class EmailOtpVerifyEndpoint extends PasswordlessEndpoint
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
            $envelope = $this->otp->signIn($email, $code, $this->client($input));
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
