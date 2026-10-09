<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\MagicLinks;
use Polaris\Passwordless\PasswordlessException;

/**
 * `POST /magic-link/send`: emails a sign-in link; the same answer for every address.
 */
final class MagicLinkSendEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly MagicLinks $links)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $email = $this->email($input);
        if ($email === null) {
            return $this->invalid('A valid email address is required.');
        }
        try {
            $this->links->send($email, self::text($input, 'redirect_uri'));
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return $this->sent();
    }
}
