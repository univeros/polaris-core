<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Http\SsoEndpoint;
use Polaris\Sso\SsoException;
use Polaris\Sso\SsoService;

/**
 * Single logout at `/sso/slo/{providerId}`, both bindings: an IdP's LogoutRequest ends the user's
 * sessions and is answered with the LogoutResponse redirect; an IdP's LogoutResponse ends an
 * application-initiated logout, whose sessions ended when the request was sent.
 */
abstract class SloEndpoint extends SsoEndpoint
{
    public function __construct(private readonly SsoService $sso)
    {
    }

    protected function singleLogout(Input $input, bool $deflated): Result
    {
        if (self::text($input->get('SAMLRequest')) !== null) {
            $message = [];
            foreach (['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'] as $field) {
                if (self::text($input->get($field)) !== null) {
                    $message[$field] = (string) $input->get($field);
                }
            }
            try {
                $url = $this->sso->idpLogout((string) $input->get('providerId'), $message, $deflated, $this->client($input));
            } catch (SsoException $exception) {
                return $this->refuse($exception);
            }

            return $url === null ? $this->respond(200, ['data' => ['status' => 'logged_out']]) : new Result(302, [], ['Location' => $url]);
        }
        if (self::text($input->get('SAMLResponse')) !== null) {
            return $this->respond(200, ['data' => ['status' => 'logged_out']]);
        }

        return $this->problem(422, 'sso/invalid_input', 'Invalid input', 'A SAMLRequest or a SAMLResponse is required.');
    }
}
