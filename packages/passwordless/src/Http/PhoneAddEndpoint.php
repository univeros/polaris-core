<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\PhoneSignIn;

/**
 * `POST /phone/add`: texts a confirmation code to a number the caller wants to add; the same answer for every number.
 */
final class PhoneAddEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly PhoneSignIn $phones)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $phone = self::text($input, 'phone');
        if ($phone === null) {
            return $this->invalid('phone is required.');
        }
        try {
            $this->phones->add($this->actorId($token), $phone);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->sent();
    }
}
