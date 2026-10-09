<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Http;

use Override;
use Polaris\Anonymous\Guests;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /anonymous/sign-in`: a new guest and its session.
 */
final class SignInEndpoint extends Endpoint
{
    public function __construct(private readonly Guests $guests)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return $this->respond(201, ['data' => $this->guests->signIn($this->client($input))]);
    }
}
