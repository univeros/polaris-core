<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Ciba;
use Polaris\OAuth\Clients;

/**
 * `GET /oauth2/ciba/pending`: the backchannel requests waiting for the caller's decision, with the
 * client behind each.
 */
final class CibaPendingEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Ciba $ciba, private readonly Clients $clients)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $data = [];
        foreach ($this->ciba->pending($this->actorId($token)) as $request) {
            $data[] = [...$request->toArray(), 'client' => $this->clients->find($request->clientId)?->toPublicArray()];
        }

        return new Result(200, ['data' => $data], self::NO_STORE);
    }
}
