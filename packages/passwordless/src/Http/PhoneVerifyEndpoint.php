<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\PhoneSignIn;

/**
 * `POST /phone/verify`: signs in with a phone code.
 */
final class PhoneVerifyEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly PhoneSignIn $phones)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $phone = self::text($input, 'phone');
        $code = self::text($input, 'code');
        if ($phone === null || $code === null) {
            return $this->invalid('phone and code are required.');
        }
        try {
            $envelope = $this->phones->signIn($phone, $code, $this->client($input));
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
