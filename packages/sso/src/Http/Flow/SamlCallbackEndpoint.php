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
 * `POST /sso/callback/{providerId}`: the SAML response (POST binding); the browser is sent on to the
 * application with the hand-off code.
 */
final class SamlCallbackEndpoint extends SsoEndpoint
{
    public function __construct(private readonly SsoService $sso)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $url = $this->sso->completeSaml((string) $input->get('providerId'), self::text($input->get('SAMLResponse')), self::text($input->get('RelayState')), $this->client($input));
        } catch (SsoException $exception) {
            return $this->refuse($exception);
        }

        return new Result(302, [], ['Location' => $url]);
    }
}
