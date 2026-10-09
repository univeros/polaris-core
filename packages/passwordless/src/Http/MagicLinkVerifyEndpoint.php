<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passwordless\MagicLinks;
use Polaris\Passwordless\PasswordlessException;

/**
 * `GET /magic-link/verify`: the link from the email; redirects to the application with a one-minute code.
 */
final class MagicLinkVerifyEndpoint extends PasswordlessEndpoint
{
    public function __construct(private readonly MagicLinks $links)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = self::text($input, 'token');
        if ($token === null) {
            return $this->invalid('token is required.');
        }
        try {
            $url = $this->links->verify($token, $this->client($input));
        } catch (PasswordlessException $exception) {
            return $this->refuse($exception);
        }

        return new Result(302, [], ['Location' => $url]);
    }
}
