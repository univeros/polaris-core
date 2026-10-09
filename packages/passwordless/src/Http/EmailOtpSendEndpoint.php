<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\EmailOtp;

use function array_key_exists;
use function implode;
use function array_keys;

/**
 * `POST /email-otp/send`: emails a code to sign in, verify the email or reset the password; the same answer for every address.
 */
final class EmailOtpSendEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly EmailOtp $otp)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $email = $this->email($input);
        $purpose = self::text($input, 'purpose') ?? EmailOtp::SIGN_IN;
        if ($email === null) {
            return $this->invalid('A valid email address is required.');
        }
        if (!array_key_exists($purpose, EmailOtp::PURPOSES)) {
            return $this->invalid('purpose must be one of ' . implode(', ', array_keys(EmailOtp::PURPOSES)) . '.');
        }
        $this->otp->send($email, $purpose);

        return $this->sent();
    }
}
