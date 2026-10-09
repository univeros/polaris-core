<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\OneTimeTokens;
use Polaris\Passwordless\PasswordlessException;

/**
 * `POST /one-time-token/verify`: the token for a session, once.
 */
final class OneTimeTokenVerifyEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly OneTimeTokens $tokens)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $value = self::text($input, 'token');
        if ($value === null) {
            return $this->invalid('token is required.');
        }
        try {
            $envelope = $this->tokens->verify($value, $this->client($input));
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
