<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passkey\PasskeyService;

/**
 * `POST /passkey/authenticate/options`: the request options for `navigator.credentials.get()`,
 * discoverable (no credential named), for a sign-in or a second factor.
 */
final class AuthenticateOptionsEndpoint extends PasskeyEndpoint
{
    public function __construct(private readonly PasskeyService $passkeys)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return $this->respond(200, ['data' => $this->passkeys->authenticateOptions()]);
    }
}
