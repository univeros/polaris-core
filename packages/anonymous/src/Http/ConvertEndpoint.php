<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Http;

use Override;
use Polaris\Anonymous\AnonymousException;
use Polaris\Anonymous\Guests;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function is_string;

/**
 * `POST /anonymous/convert`: the guest (the bearer) becomes the account of `access_token`.
 */
final class ConvertEndpoint extends Endpoint
{
    public function __construct(private readonly Guests $guests)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $accessToken = $input->get('access_token');
        if (!is_string($accessToken) || $accessToken === '') {
            return $this->problem(422, 'anonymous/invalid_input', 'Invalid input', 'access_token is required.', ['errors' => ['access_token is required.']]);
        }
        try {
            $converted = $this->guests->convert($this->actorId($token), $accessToken);
        } catch (AnonymousException $exception) {
            return $exception->reason === AnonymousException::NOT_A_GUEST
                ? $this->problem(403, 'anonymous/not_a_guest', 'Not a guest', $exception->getMessage())
                : $this->problem(422, 'anonymous/token_invalid', 'Invalid token', $exception->getMessage());
        }

        return $this->respond(200, ['data' => [...$converted, 'status' => 'converted']]);
    }
}
