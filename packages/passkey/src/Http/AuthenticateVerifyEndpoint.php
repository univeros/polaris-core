<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passkey\PasskeyException;
use Polaris\Passkey\PasskeyService;

/**
 * `POST /passkey/authenticate/verify`: signs in with the assertion.
 */
final class AuthenticateVerifyEndpoint extends PasskeyEndpoint
{
    public function __construct(private readonly PasskeyService $passkeys)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $credential = self::credential($input);
        if ($credential === null) {
            return $this->invalid('credential is required.');
        }
        try {
            $envelope = $this->passkeys->authenticate($credential, $this->client($input));
        } catch (PasskeyException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
