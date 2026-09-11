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
 * `POST /sso/exchange`: the hand-off code for the session, once.
 */
final class ExchangeEndpoint extends SsoEndpoint
{
    public function __construct(private readonly SsoService $sso)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $code = self::text($input->get('code'));
        if ($code === null) {
            return $this->problem(422, 'sso/invalid_input', 'Invalid input', 'code is required.');
        }
        try {
            $data = $this->sso->exchange($code);
        } catch (SsoException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $data]);
    }
}
