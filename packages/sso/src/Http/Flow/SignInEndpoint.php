<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Http\SsoEndpoint;
use Polaris\Sso\SsoException;
use Polaris\Sso\SsoService;

/**
 * `POST /sso/sign-in`: where the browser goes to sign in with the provider of an email's domain or of a
 * provider id.
 */
final class SignInEndpoint extends SsoEndpoint
{
    public function __construct(private readonly SsoService $sso)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $started = $this->sso->start(self::text($input->get('email')), self::text($input->get('provider_id')), self::text($input->get('redirect_uri')));
        } catch (SsoException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $started]);
    }
}
