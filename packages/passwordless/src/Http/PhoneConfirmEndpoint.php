<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\PhoneSignIn;

/**
 * `POST /phone/confirm`: attaches the number with its confirmation code.
 */
final class PhoneConfirmEndpoint extends PasswordlessEndpoint
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
        $code = self::text($input, 'code');
        if ($phone === null || $code === null) {
            return $this->invalid('phone and code are required.');
        }
        try {
            $e164 = $this->phones->confirm($this->actorId($token), $phone, $code);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['phone' => $e164, 'verified' => true]]);
    }
}
