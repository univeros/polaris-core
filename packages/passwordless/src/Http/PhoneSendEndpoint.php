<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\PhoneSignIn;

/**
 * `POST /phone/send`: texts a sign-in code to a verified phone; the same answer for every number.
 */
final class PhoneSendEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly PhoneSignIn $phones)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $phone = self::text($input, 'phone');
        if ($phone === null) {
            return $this->invalid('phone is required.');
        }
        try {
            $this->phones->send($phone);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->sent();
    }
}
