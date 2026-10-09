<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\OneTimeTokens;
use Polaris\Passwordless\PasswordlessException;

/**
 * `POST /one-time-token/generate`: a three-minute token that opens a session like the caller's elsewhere.
 */
final class OneTimeTokenGenerateEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly OneTimeTokens $tokens)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $generated = $this->tokens->generate($token);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(201, ['data' => $generated]);
    }
}
