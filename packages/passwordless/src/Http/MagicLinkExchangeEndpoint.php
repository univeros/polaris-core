<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\Sessions;

/**
 * `POST /magic-link/exchange`: the redirect's code for the login envelope, once.
 */
final class MagicLinkExchangeEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly Sessions $sessions)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $code = self::text($input, 'code');
        if ($code === null) {
            return $this->invalid('code is required.');
        }
        try {
            $envelope = $this->sessions->exchange($code);
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
